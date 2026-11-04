#!/usr/bin/env python3
"""Tests for the per-machine local model choice (fit to hardware, and who gets switched on).
Run:  python3 backend/tools/test_autotune_local_models.py"""
import os
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path[:0] = [HERE, os.path.join(os.path.dirname(HERE), 'agents'), os.path.dirname(HERE)]
import autotune_local_models as at  # noqa: E402


def w(j, fpr=0.1):
    return {'youden_lb': j, 'fpr': fpr, 'recall': 0.8}


class Fit(unittest.TestCase):
    def test_small_gpu_takes_the_small_models_only(self):
        hw = {'gpu': {'vram_gb': 8.0}, 'ram_gb': 8.0}
        self.assertEqual(at.fit('hermes3', hw), 'gpu')           # 4.7 GB * 1.25 fits in 8
        self.assertIsNone(at.fit('phi4:14b', hw))                # 9 GB fits neither the card nor 8 GB of memory

    def test_no_gpu_uses_memory_and_leaves_room(self):
        self.assertEqual(at.fit('mistral', {'gpu': None, 'ram_gb': 16}), 'cpu')
        self.assertIsNone(at.fit('mistral', {'gpu': None, 'ram_gb': 8}))

    def test_unknown_model_is_treated_as_large(self):
        self.assertIsNone(at.fit('mystery:70b', {'gpu': {'vram_gb': 8.0}, 'ram_gb': 8}))


class Choose(unittest.TestCase):
    def doc(self, weights, n=40, provisional=False):
        return {'provisional': provisional, 'n_per_class': n, 'weights': weights}

    def test_best_first_and_capped(self):
        chosen, why = at.choose(self.doc({'a': w(.5), 'b': w(.9), 'c': w(.7), 'd': w(.6)}), 2, .35)
        self.assertEqual(chosen, ['b', 'c'])
        self.assertIn('d', why)

    def test_rejects_chance_and_false_alarms(self):
        chosen, why = at.choose(self.doc({'a': w(0), 'b': w(.8, fpr=.5), 'c': w(.4)}), 3, .35)
        self.assertEqual(chosen, ['c'])
        self.assertEqual(set(why), {'a', 'b'})

    def test_small_run_chooses_nothing(self):
        chosen, why = at.choose(self.doc({'a': w(.9)}, n=15, provisional=True), 3, .35)
        self.assertEqual(chosen, [])
        self.assertIn('*', why)


if __name__ == '__main__':
    unittest.main()
