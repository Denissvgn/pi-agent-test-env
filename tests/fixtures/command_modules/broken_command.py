"""Module that fails while importing; used to prove that such a module stops the program."""
raise RuntimeError('synthetic import failure')
