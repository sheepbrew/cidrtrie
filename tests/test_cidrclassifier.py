# Copyright (c) 2015 Uber Technologies, Inc.
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.

from cidrtrie import CidrClassifier
import unittest


class CidrClassifierTestCase(unittest.TestCase):
    def test_basic(self):
        c = CidrClassifier()
        # ECMP path
        c.add_mapping('192.168.0.0', 24, 'HopA')
        c.add_mapping('192.168.0.0', 24, 'HopB')
        self.assertEqual(c.lookup('192.168.0.1'), ('192.168.0.0', 24, ['HopA', 'HopB']))

        # non-ECMP path because of different mask
        c.add_mapping('192.168.0.0', 26, 'HopA')
        c.add_mapping('192.168.0.0', 27, 'HopC')
        self.assertEqual(c.lookup('192.168.0.1'), ('192.168.0.0', 27, ['HopC']))

        c.remove_mapping('192.168.0.0', 27, 'HopC')
        self.assertEqual(c.lookup('192.168.0.1'), ('192.168.0.0', 26, ['HopA']))

        c.remove_mapping('192.168.0.0', 26, 'HopA')
        self.assertEqual(c.lookup('192.168.0.1'), ('192.168.0.0', 24, ['HopA', 'HopB']))

        c.remove_mapping('192.168.0.0', 24, 'HopB')
        self.assertEqual(c.lookup('192.168.0.1'), ('192.168.0.0', 24, ['HopA']))

        c.add_mapping('192.168.0.0', 24, 'HopC')
        self.assertEqual(c.lookup('192.168.0.1'), ('192.168.0.0', 24, ['HopA', 'HopC']))

        c.remove_mapping('192.168.0.0', 24, 'HopA')
        c.remove_mapping('192.168.0.0', 24, 'HopC')

        self.assertRaises(KeyError, lambda: c.lookup('192.168.0.0'))

# vim: set textwidth=120:
