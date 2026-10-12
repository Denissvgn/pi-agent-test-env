"""Offline GitHub review-state fixtures; no network or repository mutation."""
import contextlib
import copy
import io
import json
from pathlib import Path
import sys
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'skill/scripts'))
import pr_review_gate as gate

HEAD = 'a' * 40
OLD = 'b' * 40


def snapshot():
    return {'pr': {'head': {'sha': HEAD}, 'state': 'open', 'draft': False,
                   'mergeable_state': 'clean', 'requested_reviewers': [], 'requested_teams': [],
                   'updated_at': '2026-10-12T20:00:00Z'},
            'reviews': [{'id': 1, 'user': {'login': 'copilot-pull-request-reviewer[bot]'},
                         'state': 'COMMENTED', 'commit_id': HEAD, 'submitted_at': '2026-10-12T20:00:00Z'}],
            'threads': [], 'review_decision': None, 'checks': [], 'statuses': [],
            'status_summary': {'sha': HEAD, 'state': 'pending', 'total_count': 0}}


class ReviewGateTests(unittest.TestCase):
    def evaluate(self, state):
        return gate.evaluate(state, 'owner/repository', 3, HEAD, ['Copilot'])

    def test_clean_exact_head_completed_review_is_ready(self):
        result = self.evaluate(snapshot())
        self.assertEqual(result['status'], 'PASS')
        self.assertEqual(result['completed_reviews'][0]['head'], HEAD)

    def test_mergeable_before_async_review_is_not_ready(self):
        state = snapshot(); state['reviews'] = []
        result = self.evaluate(state)
        self.assertEqual(result['status'], 'BLOCKED')
        self.assertIn('No completed exact-head review from Copilot', result['blockers'])

    def test_stale_dismissed_pending_and_other_author_do_not_substitute(self):
        for fault in ('stale', 'dismissed', 'pending', 'other-author', 'no-submission'):
            state = snapshot(); review = state['reviews'][0]
            if fault == 'stale': review['commit_id'] = OLD
            elif fault == 'dismissed': review['state'] = 'DISMISSED'
            elif fault == 'pending': review['state'] = 'PENDING'
            elif fault == 'other-author': review['user']['login'] = 'someone-else'
            else: review['submitted_at'] = None
            with self.subTest(fault=fault):
                if fault == 'no-submission':
                    with self.assertRaises(ValueError): self.evaluate(state)
                else: self.assertEqual(self.evaluate(state)['status'], 'BLOCKED')

    def test_outdated_unresolved_threads_still_block(self):
        for outdated in (False, True):
            state = snapshot(); state['threads'] = [{'id': 'thread', 'isResolved': False, 'isOutdated': outdated,
                                                     'path': 'code.py', 'comments': {'nodes': [{'url': 'https://example.invalid/thread'}]}}]
            self.assertEqual(self.evaluate(state)['status'], 'BLOCKED')
            state['threads'][0]['isResolved'] = True
            self.assertEqual(self.evaluate(state)['status'], 'PASS')

    def test_commented_review_does_not_clear_request_changes(self):
        state = snapshot(); prior = copy.deepcopy(state['reviews'][0]); prior['state'] = 'CHANGES_REQUESTED'; prior['commit_id'] = OLD
        state['reviews'].insert(0, prior)
        self.assertEqual(self.evaluate(state)['status'], 'BLOCKED')
        state['reviews'][-1]['state'] = 'APPROVED'
        self.assertEqual(self.evaluate(state)['status'], 'PASS')

    def test_server_requirements_and_pending_requests_block(self):
        for fault in ('requested-human', 'requested-team', 'review-required', 'changes-requested', 'draft', 'closed', 'merge-unknown', 'wrong-head'):
            state = snapshot()
            if fault == 'requested-human': state['pr']['requested_reviewers'] = [{'login': 'human'}]
            elif fault == 'requested-team': state['pr']['requested_teams'] = [{'slug': 'team'}]
            elif fault == 'review-required': state['review_decision'] = 'REVIEW_REQUIRED'
            elif fault == 'changes-requested': state['review_decision'] = 'CHANGES_REQUESTED'
            elif fault == 'draft': state['pr']['draft'] = True
            elif fault == 'closed': state['pr']['state'] = 'closed'
            elif fault == 'merge-unknown': state['pr']['mergeable_state'] = 'unknown'
            else: state['pr']['head']['sha'] = OLD
            with self.subTest(fault=fault): self.assertEqual(self.evaluate(state)['status'], 'BLOCKED')

    def test_missing_pending_review_fields_are_not_empty_requests(self):
        for field in ('requested_reviewers', 'requested_teams'):
            state = snapshot(); del state['pr'][field]
            self.assertEqual(self.evaluate(state)['status'], 'BLOCKED')

    def test_checks_are_completed_and_bound_to_verified_head(self):
        for fault in ('running', 'failed', 'stale', 'status-pending'):
            state = snapshot(); state['checks'] = [{'name': 'tests', 'head_sha': HEAD, 'status': 'completed', 'conclusion': 'success'}]
            if fault == 'running': state['checks'][0]['status'] = 'in_progress'
            elif fault == 'failed': state['checks'][0]['conclusion'] = 'failure'
            elif fault == 'stale': state['checks'][0]['head_sha'] = OLD
            else: state['statuses'] = [{'context': 'external', 'state': 'pending'}]
            with self.subTest(fault=fault): self.assertEqual(self.evaluate(state)['status'], 'BLOCKED')

    def test_thread_pagination_reads_late_unresolved_finding(self):
        def page(nodes, more=False, cursor=None):
            return {'data': {'repository': {'pullRequest': {'headRefOid': HEAD, 'reviewDecision': None,
                      'reviewThreads': {'nodes': nodes, 'totalCount': 2, 'pageInfo': {'hasNextPage': more, 'endCursor': cursor}}}}}}
        with mock.patch.object(gate, 'api', side_effect=[page([{'id': 'resolved', 'isResolved': True, 'isOutdated':False, 'path':'a.py'}], True, 'next'),
                                                      page([{'id': 'late', 'isResolved': False, 'isOutdated':False, 'path':'b.py'}])]) as api:
            rows, decision = gate.threads('owner/repository', 3, HEAD)
        self.assertEqual(len(rows), 2)
        self.assertIn('after=next', api.call_args_list[1].args[0])
        state = snapshot(); state['threads'] = rows
        self.assertEqual(self.evaluate(state)['status'], 'BLOCKED')

    def test_incomplete_pagination_and_changed_head_fail_closed(self):
        for fault in ('missing-cursor', 'changed-head'):
            page = {'data': {'repository': {'pullRequest': {'headRefOid': HEAD, 'reviewDecision': None,
                     'reviewThreads': {'nodes': [], 'totalCount': 1, 'pageInfo': {'hasNextPage': True, 'endCursor': None}}}}}}
            if fault == 'changed-head': page['data']['repository']['pullRequest']['headRefOid'] = OLD
            with self.subTest(fault=fault), mock.patch.object(gate, 'api', return_value=page), self.assertRaises(ValueError):
                gate.threads('owner/repository', 3, HEAD)

    def test_changes_during_collection_cannot_yield_ready_receipt(self):
        before = snapshot()['pr']; after = copy.deepcopy(before); after['updated_at'] = '2026-10-12T20:01:00Z'
        with mock.patch.object(gate, 'api', side_effect=[before, after]), \
             mock.patch.object(gate, 'pages', return_value=[]), mock.patch.object(gate, 'threads', return_value=([], None)), \
             mock.patch.object(gate, 'combined_status', return_value=([], snapshot()['status_summary'])), self.assertRaises(ValueError):
            gate.collect('owner/repository', 3, HEAD)

    def test_check_or_status_churn_blocks_even_with_unchanged_pr_timestamp(self):
        before = snapshot()['pr']
        check={'id':1,'name':'tests','head_sha':HEAD,'status':'completed','conclusion':'success'}
        success=[{'context':'external','state':'success','id':1}]
        success_summary={'sha':HEAD,'state':'success','total_count':1}
        for fault in ('check-rerun','status-change','new-thread','new-review'):
            with self.subTest(fault=fault):
                checks2=[{**check,'status':'in_progress','conclusion':None}] if fault=='check-rerun' else [check]
                statuses2=[{**success[0],'state':'pending','id':2}] if fault=='status-change' else success
                summary2={**success_summary,'state':'pending'} if fault=='status-change' else success_summary
                threads2=[{'id':'late','isResolved':False}] if fault=='new-thread' else []
                reviews2=snapshot()['reviews'] if fault=='new-review' else []
                with mock.patch.object(gate,'api',return_value=before), \
                     mock.patch.object(gate,'pages',side_effect=[[],[check],reviews2,checks2]), \
                     mock.patch.object(gate,'threads',side_effect=[([],None),(threads2,None)]), \
                     mock.patch.object(gate,'combined_status',side_effect=[(success,success_summary),(statuses2,summary2)]), self.assertRaises(ValueError):
                    gate.collect('owner/repository',3,HEAD)

    def test_stable_collection_revalidates_all_sources_before_readiness(self):
        state=snapshot()
        with mock.patch.object(gate,'api',return_value=state['pr']), \
             mock.patch.object(gate,'pages',side_effect=[state['reviews'],[],state['reviews'],[]]) as pages, \
             mock.patch.object(gate,'threads',return_value=([],None)) as threads, \
             mock.patch.object(gate,'combined_status',return_value=([],state['status_summary'])) as statuses:
            collected=gate.collect('owner/repository',3,HEAD)
        self.assertEqual(self.evaluate(collected)['status'],'PASS')
        self.assertEqual(pages.call_count,4);self.assertEqual(threads.call_count,2);self.assertEqual(statuses.call_count,2)

    def test_status_pages_are_complete_and_preserve_late_failures(self):
        visible = [{'context': 'check-'+str(i), 'state': 'success'} for i in range(100)]
        first = {'sha': HEAD, 'state': 'failure', 'total_count': 101, 'statuses': visible}
        final = {**first, 'statuses': [{'context': 'last', 'state': 'failure'}]}
        with mock.patch.object(gate, 'api', return_value=[first, final]):
            rows, summary = gate.combined_status('owner/repository', HEAD)
        state = snapshot(); state.update(statuses=rows, status_summary=summary)
        self.assertEqual(self.evaluate(state)['status'], 'BLOCKED')
        with mock.patch.object(gate, 'api', return_value=[first]), self.assertRaises(ValueError):
            gate.combined_status('owner/repository', HEAD)

    def test_status_sha_aggregate_and_coverage_cannot_be_ignored(self):
        for fault in ('sha', 'count', 'aggregate', 'duplicate'):
            page = {'sha': HEAD, 'state': 'success', 'total_count': 1, 'statuses': [{'context': 'tests', 'state': 'success'}]}
            if fault == 'sha': page['sha'] = OLD
            elif fault == 'count': page['total_count'] = 2
            elif fault == 'aggregate': page['state'] = 'failure'
            else: page['total_count'] = 2; page['statuses'] *= 2
            with self.subTest(fault=fault), mock.patch.object(gate, 'api', return_value=[page]):
                if fault == 'aggregate':
                    rows, summary = gate.combined_status('owner/repository', HEAD)
                    state = snapshot(); state.update(statuses=rows, status_summary=summary)
                    self.assertEqual(self.evaluate(state)['status'], 'BLOCKED')
                else:
                    with self.assertRaises(ValueError): gate.combined_status('owner/repository', HEAD)

    def test_check_run_count_and_unknown_thread_completion_fail_closed(self):
        with mock.patch.object(gate, 'api', return_value=[{'total_count':2,'check_runs':[{'name':'visible','status':'completed','conclusion':'success'}]}]), self.assertRaises(ValueError):
            gate.pages('synthetic', 'check_runs')
        page={'data':{'repository':{'pullRequest':{'headRefOid':HEAD,'reviewDecision':None,
             'reviewThreads':{'nodes':[],'totalCount':1,'pageInfo':{'hasNextPage':None,'endCursor':None}}}}}}
        with mock.patch.object(gate, 'api', return_value=page), self.assertRaises(ValueError):
            gate.threads('owner/repository',3,HEAD)

    def test_unknown_review_enums_and_thread_metadata_cannot_pass(self):
        state=snapshot();state['review_decision']='UNKNOWN'
        self.assertEqual(self.evaluate(state)['status'],'BLOCKED')
        state=snapshot();state['reviews'].append({**state['reviews'][0],'state':'UNKNOWN'})
        with self.assertRaises(ValueError):self.evaluate(state)
        state=snapshot();state['threads']=[{'id':'unknown','isResolved':True,'isOutdated':None,'path':'a.py'}]
        with self.assertRaises(ValueError):self.evaluate(state)

    def test_duplicate_pages_cannot_hide_an_omitted_finding_or_check(self):
        row={'id':1,'name':'visible','head_sha':HEAD,'status':'completed','conclusion':'success'}
        with mock.patch.object(gate,'api',return_value=[{'total_count':2,'check_runs':[row]},{'total_count':2,'check_runs':[row]}]),self.assertRaises(ValueError):
            gate.pages('synthetic','check_runs')
        thread={'id':'same','isResolved':True,'isOutdated':False,'path':'a.py'}
        def page(more,cursor):
            return {'data':{'repository':{'pullRequest':{'headRefOid':HEAD,'reviewDecision':None,
              'reviewThreads':{'nodes':[thread],'totalCount':2,'pageInfo':{'hasNextPage':more,'endCursor':cursor}}}}}}
        with mock.patch.object(gate,'api',side_effect=[page(True,'next'),page(False,None)]),self.assertRaises(ValueError):
            gate.threads('owner/repository',3,HEAD)

    def test_invalid_submission_timestamp_is_not_completed_review_evidence(self):
        for submitted in ('not-a-timestamp','2026-10-12T20:00:00'):
            state=snapshot();state['reviews'][0]['submitted_at']=submitted
            with self.subTest(submitted=submitted),self.assertRaises(ValueError):self.evaluate(state)

    def test_cli_api_failure_is_sanitized_and_blocks(self):
        output = io.StringIO()
        with mock.patch.object(gate, 'collect', side_effect=ValueError('private diagnostic')), contextlib.redirect_stdout(output):
            code = gate.main(['--repo', 'owner/repository', '--pr', '3', '--head', HEAD])
        self.assertEqual(code, 2); self.assertNotIn('private diagnostic', output.getvalue())
        self.assertEqual(json.loads(output.getvalue())['status'], 'BLOCKED')


if __name__ == '__main__': unittest.main()
