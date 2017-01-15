#
# ndmtk - Network Discovery and Management Toolkit
# Copyright (C) 2016 Paul Greenberg @greenpau
# See LICENSE.txt for licensing details
#

from __future__ import print_function;
import unittest;
import os;
import sys;

class UtilitiesTest(unittest.TestCase):

    @staticmethod
    def _find_utility(name):
        x = any(os.access(os.path.join(path, name), os.X_OK) for path in os.environ["PATH"].split(os.pathsep));
        return x;


    def test_is_ssh_available(self):
        rst = self._find_utility('ssh');
        try:
            self.assertTrue(rst, 'ssh client is not found');
        except:
            e = sys.exc_info();
            raise e[0], e[1], e[2].tb_next;

    def test_is_expect_available(self):
        rst = self._find_utility('expect');
        try:
            self.assertTrue(rst, 'expect utility is not found');
        except:
            e = sys.exc_info();
            raise e[0], e[1], e[2].tb_next;

def main():
    unittest.main();

if __name__ == "__main__":
    main();
