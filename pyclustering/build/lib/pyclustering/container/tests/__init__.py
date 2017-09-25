"""!

@brief Unit-test runner for containers.

@authors Andrei Novikov (pyclustering@yandex.ru)
@date 2014-2017
@copyright GNU Public License

@cond GNU_PUBLIC_LICENSE
    PyClustering is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.
    
    PyClustering is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.
    
    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
@endcond

"""

import unittest;

from pyclustering.container.tests                   import cftree_tests        as container_cftree_unit_tests;
from pyclustering.container.tests                   import kdtree_tests        as container_kdtree_unit_tests;

if __name__ == "__main__":
    suite = unittest.TestSuite();

    suite.addTests(unittest.TestLoader().loadTestsFromModule(container_cftree_unit_tests));
    suite.addTests(unittest.TestLoader().loadTestsFromModule(container_kdtree_unit_tests));
    
    unittest.TextTestRunner(verbosity = 2).run(suite);