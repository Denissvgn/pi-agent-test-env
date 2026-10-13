#!/usr/bin/env python3
"""Read-only, exact-head GitHub merge readiness. Never merge or resolve findings."""
import argparse
import datetime
import json
import re
import subprocess


def reviewer_name(name):
    name = (name or '').lower().removesuffix('[bot]')
    return 'copilot' if name in ('copilot', 'copilot-pull-request-reviewer') else name


def review_performed(row):
    """Copilot can submit COMMENTED quota/error notices without reviewing code."""
    if reviewer_name(row.get('user', {}).get('login')) != 'copilot':
        return True
    body = row.get('body')
    if not isinstance(body, str):
        return False
    # Require the completion overview observed on this repository's real reviews.
    # Empty submissions, refusal notices and unknown formats fail closed.
    return (body.lstrip().startswith('<!-- ccr-overview-v2 -->')
            and re.search(r'^### [^\n]*(?:Approval|Changes) recommended\s*$', body, re.M) is not None
            and re.search(r'\b\d+ open findings?\b', body) is not None)


def api(arguments):
    result = subprocess.run(['gh', 'api', *arguments], capture_output=True, text=True, timeout=30)
    if result.returncode:
        raise ValueError('GitHub review evidence unavailable; no merge readiness established')
    value = json.loads(result.stdout)
    if isinstance(value, dict) and value.get('errors'):
        raise ValueError('GitHub returned incomplete GraphQL review evidence')
    return value


def pages(path, key=None):
    values = api([path, '--paginate', '--slurp'])
    if not isinstance(values, list):
        raise ValueError('Malformed paginated GitHub evidence')
    output = []; total = None
    for page in values:
        rows = page.get(key) if key and isinstance(page, dict) else page
        if not isinstance(rows, list) or not all(isinstance(row, dict) for row in rows):
            raise ValueError('Malformed GitHub review/check page')
        if key:
            count = page.get('total_count')
            if type(count) is not int or count < 0 or total is not None and count != total:
                raise ValueError('Check coverage is unknown or changed during pagination')
            total = count
        output.extend(rows)
    if key and (total is None or total != len(output)):
        raise ValueError('Check pagination coverage is incomplete')
    if (not all(type(row.get('id')) is int and row['id'] > 0 for row in output)
            or len({row['id'] for row in output}) != len(output)):
        raise ValueError('Review/check pagination identities are missing or duplicated')
    return output


THREAD_QUERY = '''query($owner:String!,$name:String!,$number:Int!,$after:String) {
  repository(owner:$owner,name:$name) { pullRequest(number:$number) {
    headRefOid reviewDecision reviewThreads(first:100,after:$after) {
      totalCount pageInfo { hasNextPage endCursor }
      nodes { id isResolved isOutdated path line comments(first:1) { nodes { url } } }
    }
  } }
}'''


def threads(repo, number, head):
    owner, name = repo.split('/')
    cursor = None; seen = set(); rows = []; decision = None; total = None
    for _ in range(100):
        arguments = ['graphql', '-f', 'query=' + THREAD_QUERY, '-f', 'owner=' + owner,
                     '-f', 'name=' + name, '-F', 'number=' + str(number)]
        if cursor:
            arguments += ['-f', 'after=' + cursor]
        pr = api(arguments)['data']['repository']['pullRequest']
        if pr['headRefOid'] != head:
            raise ValueError('PR head changed while reading review threads')
        decision = pr['reviewDecision']
        connection = pr['reviewThreads']
        if not isinstance(connection['nodes'], list):
            raise ValueError('Malformed review thread connection')
        count = connection['totalCount']
        if type(count) is not int or count < 0 or total is not None and count != total:
            raise ValueError('Review thread coverage is unknown or changed')
        total = count
        rows.extend(connection['nodes'])
        if (not all(isinstance(row, dict) and isinstance(row.get('id'), str) and row['id'] for row in rows)
                or len({row['id'] for row in rows}) != len(rows)):
            raise ValueError('Review thread identities are missing or duplicated')
        info = connection['pageInfo']
        if type(info['hasNextPage']) is not bool:
            raise ValueError('Review thread pagination completion is unknown')
        if not info['hasNextPage']:
            if len(rows) != total:
                raise ValueError('Review thread pagination coverage is incomplete')
            return rows, decision
        cursor = info['endCursor']
        if not cursor or cursor in seen:
            raise ValueError('Incomplete review thread pagination')
        seen.add(cursor)
    raise ValueError('Review thread limit exceeded; coverage is incomplete')


def combined_status(repo, head):
    values = api(['repos/' + repo + '/commits/' + head + '/status?per_page=100', '--paginate', '--slurp'])
    if not isinstance(values, list) or not values:
        raise ValueError('Combined commit status evidence unavailable')
    rows = []; identity = None
    for page in values:
        if (not isinstance(page, dict) or page.get('sha') != head
                or type(page.get('total_count')) is not int or page['total_count'] < 0
                or page.get('state') not in ('success', 'failure', 'pending')
                or not isinstance(page.get('statuses'), list)):
            raise ValueError('Malformed combined commit status evidence')
        current = (page['sha'], page['state'], page['total_count'])
        if identity is not None and current != identity:
            raise ValueError('Commit status changed during pagination')
        identity = current
        rows.extend(page['statuses'])
    if (len(rows) != identity[2] or not all(isinstance(row, dict) and isinstance(row.get('context'), str) for row in rows)
            or len({row['context'] for row in rows}) != len(rows)):
        raise ValueError('Commit status coverage is incomplete or ambiguous')
    return rows, {'sha': identity[0], 'state': identity[1], 'total_count': identity[2]}


def collect(repo, number, head):
    path = 'repos/' + repo + '/pulls/' + str(number)
    before = api([path])
    if before['head']['sha'] != head:
        raise ValueError('Expected head differs from the live PR head')
    reviews = pages(path + '/reviews?per_page=100')
    review_threads, decision = threads(repo, number, head)
    checks = pages('repos/' + repo + '/commits/' + head + '/check-runs?per_page=100&filter=latest', 'check_runs')
    statuses, status_summary = combined_status(repo, head)
    # CI updates need not change PR.updated_at. Re-read each independent source
    # and compare complete, identity-ordered evidence before emitting readiness.
    latest_reviews = pages(path + '/reviews?per_page=100')
    latest_threads, latest_decision = threads(repo, number, head)
    latest_checks = pages('repos/' + repo + '/commits/' + head + '/check-runs?per_page=100&filter=latest', 'check_runs')
    latest_statuses, latest_summary = combined_status(repo, head)
    def ordered(rows, key):
        return sorted(rows, key=lambda row: row[key])
    if (ordered(reviews, 'id') != ordered(latest_reviews, 'id')
            or ordered(review_threads, 'id') != ordered(latest_threads, 'id') or decision != latest_decision
            or ordered(checks, 'id') != ordered(latest_checks, 'id')
            or ordered(statuses, 'context') != ordered(latest_statuses, 'context') or status_summary != latest_summary):
        raise ValueError('Review/check/status evidence changed during collection; rerun the gate')
    after = api([path])
    if (after['head']['sha'] != head or before['updated_at'] != after['updated_at']
            or before['state'] != after['state'] or before['draft'] != after['draft']):
        raise ValueError('PR changed during evidence collection; rerun the gate')
    return {'pr': after, 'reviews': reviews, 'threads': review_threads,
            'review_decision': decision, 'checks': checks, 'statuses': statuses, 'status_summary': status_summary}


def evaluate(snapshot, repo, number, head, expected_reviewers):
    pr = snapshot['pr']; blockers = []
    if pr['head']['sha'] != head:
        blockers.append('PR head differs from the verified head')
    if pr.get('state') != 'open' or pr.get('draft') is not False:
        blockers.append('PR is not open and ready for review')
    if pr.get('mergeable_state') != 'clean':
        blockers.append('GitHub merge state is not clean')
    for field in ('requested_reviewers', 'requested_teams'):
        if not isinstance(pr.get(field), list):
            blockers.append('Pending-review evidence is incomplete: ' + field)
        elif pr[field]:
            blockers.append('Requested reviews are still pending: ' + field)
    if snapshot.get('review_decision') not in (None, 'APPROVED'):
        blockers.append('Repository review requirements are unsatisfied')

    reviews = snapshot['reviews']
    for row in reviews:
        if (not isinstance(row, dict) or row.get('state') not in ('PENDING','APPROVED','CHANGES_REQUESTED','COMMENTED','DISMISSED')
                or not isinstance(row.get('user'), dict) or not isinstance(row['user'].get('login'), str)
                or not row['user']['login'] or type(row.get('id')) is not int
                or not isinstance(row.get('commit_id'), str) or not re.fullmatch(r'[0-9a-f]{40}', row['commit_id'])
                or row['state'] != 'PENDING' and not isinstance(row.get('submitted_at'), str)):
            raise ValueError('Review state/identity evidence is unknown')
        if row['state'] != 'PENDING':
            submitted = datetime.datetime.fromisoformat(row['submitted_at'].replace('Z', '+00:00'))
            if submitted.tzinfo is None:
                raise ValueError('Review submission timestamp lacks timezone evidence')
    if any(row.get('state') == 'PENDING' for row in reviews):
        blockers.append('A review is still in progress')
    completed = []
    for expected in expected_reviewers:
        matching = [row for row in reviews if reviewer_name(row.get('user', {}).get('login')) == reviewer_name(expected)]
        fresh = [row for row in matching if row.get('commit_id') == head and row.get('submitted_at')
                 and row.get('state') in ('APPROVED', 'COMMENTED') and review_performed(row)]
        if not fresh:
            blockers.append('No completed exact-head review from ' + expected)
        else:
            completed.append({'reviewer': expected, 'review_id': fresh[-1]['id'], 'head': head})
    # A later COMMENTED review does not clear a request-changes decision.
    decisions = {}
    for row in reviews:
        if row.get('state') in ('APPROVED', 'CHANGES_REQUESTED'):
            decisions[reviewer_name(row.get('user', {}).get('login'))] = row['state']
    if 'CHANGES_REQUESTED' in decisions.values():
        blockers.append('An undismissed request-changes review remains')

    unresolved = []
    for thread in snapshot['threads']:
        if (not isinstance(thread, dict) or not isinstance(thread.get('id'), str) or not thread['id']
                or type(thread.get('isResolved')) is not bool or type(thread.get('isOutdated')) is not bool
                or not isinstance(thread.get('path'), str)):
            raise ValueError('Review thread metadata is unknown')
        if thread.get('isResolved') is not True:
            comments = thread.get('comments', {}).get('nodes', [])
            unresolved.append({'id': thread['id'], 'path': thread.get('path'),
                               'outdated': thread.get('isOutdated'), 'url': comments[0].get('url') if comments else None})
    if unresolved:
        blockers.append('Unresolved review threads remain, including outdated threads')
    for check in snapshot['checks']:
        if (check.get('head_sha') != head or check.get('status') != 'completed'
                or check.get('conclusion') not in ('success', 'neutral', 'skipped')):
            blockers.append('Incomplete/failing exact-head check: ' + check.get('name', 'unknown'))
    for status in snapshot['statuses']:
        if status.get('state') != 'success':
            blockers.append('Incomplete/failing commit status: ' + status.get('context', 'unknown'))
    combined = snapshot['status_summary']
    if (combined.get('sha') != head or combined.get('total_count') != len(snapshot['statuses'])
            or (combined.get('total_count') == 0 and combined.get('state') != 'pending')
            or (combined.get('total_count') != 0 and combined.get('state') != 'success')):
        blockers.append('Combined commit status is failing, pending or incomplete')
    return {'schema': 1, 'document_type': 'pr_review_gate', 'status': 'BLOCKED' if blockers else 'PASS',
            'repo': repo, 'pr': number, 'head': head, 'expected_reviewers': expected_reviewers,
            'completed_reviews': completed, 'unresolved_threads': unresolved, 'blockers': blockers,
            'commit_status': combined,
            'observed_at': datetime.datetime.now(datetime.timezone.utc).isoformat(),
            'scope': 'Read-only merge readiness; no external mutation or correctness proof'}


def add_arguments(parser):
    parser.add_argument('--repo', required=True)
    parser.add_argument('--pr', type=int, required=True)
    parser.add_argument('--head', required=True, help='Exact verified PR head SHA')
    parser.add_argument('--expect-reviewer', action='append', help='Required completed reviewer; defaults to Copilot')
    return parser


def command(args):
    if (not re.fullmatch(r'[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+', args.repo)
            or args.pr <= 0 or not re.fullmatch(r'[0-9a-f]{40}', args.head)):
        raise ValueError('Use owner/repository, a positive PR number and an exact 40-character head SHA')
    expected = args.expect_reviewer or ['Copilot']
    if any(not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9-]*(?:\[bot\])?', name) for name in expected):
        raise ValueError('Expected reviewers must be nonempty GitHub login names')
    try:
        result = evaluate(collect(args.repo, args.pr, args.head), args.repo, args.pr, args.head, expected)
    except (OSError, ValueError, KeyError, TypeError, AttributeError, IndexError, subprocess.TimeoutExpired) as exc:
        result = {'schema': 1, 'document_type': 'pr_review_gate', 'status': 'BLOCKED',
                  'repo': args.repo, 'pr': args.pr, 'head': args.head,
                  'blockers': ['Review evidence unavailable or incomplete'], 'error_type': type(exc).__name__}
    print(json.dumps(result, indent=2))
    return 0 if result['status'] == 'PASS' else 2


def main(argv=None):
    parser = add_arguments(argparse.ArgumentParser(description=__doc__))
    args = parser.parse_args(argv)
    try:
        return command(args)
    except ValueError as exc:
        parser.error(str(exc))


if __name__ == '__main__':
    raise SystemExit(main())
