"""!

@brief Unit-test runner for tests of clustering algorithms.

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

# Generate images without having a window appear.
import matplotlib;
matplotlib.use('Agg');


from pyclustering.cluster.tests.unit               import ut_agglomerative      as cluster_agglomerative_unit_tests;
from pyclustering.cluster.tests.unit               import ut_birch              as cluster_birch_unit_tests;
from pyclustering.cluster.tests.unit               import ut_center_initializer as cluster_center_initializer_unit_tests;
from pyclustering.cluster.tests.unit               import ut_clarans            as cluster_clarans_unit_tests;
from pyclustering.cluster.tests.unit               import ut_cure               as cluster_cure_unit_tests;
from pyclustering.cluster.tests.unit               import ut_dbscan             as cluster_dbscan_unit_tests;
from pyclustering.cluster.tests.unit               import ut_encoder            as cluster_encoder_unit_tests;
from pyclustering.cluster.tests.unit               import ut_general            as cluster_general_unit_tests;
from pyclustering.cluster.tests.unit               import ut_hsyncnet           as cluster_hsyncnet_unit_tests;
from pyclustering.cluster.tests.unit               import ut_kmeans             as cluster_kmeans_unit_tests;
from pyclustering.cluster.tests.unit               import ut_kmedians           as cluster_kmedians_unit_tests;
from pyclustering.cluster.tests.unit               import ut_kmedoids           as cluster_kmedoids_unit_tests;
from pyclustering.cluster.tests.unit               import ut_optics             as cluster_optics_unit_tests;
from pyclustering.cluster.tests.unit               import ut_rock               as cluster_rock_unit_tests;
from pyclustering.cluster.tests.unit               import ut_somsc              as cluster_somsc_unit_tests;
from pyclustering.cluster.tests.unit               import ut_syncnet            as cluster_syncnet_unit_tests;
from pyclustering.cluster.tests.unit               import ut_syncsom            as cluster_syncsom_unit_tests;
from pyclustering.cluster.tests.unit               import ut_xmeans             as cluster_xmeans_unit_tests;


class clustering_unit_tests:
    def __init__(self):
        self.__suite = unittest.TestSuite();
        self.fill_suite(self.__suite);


    def get_suite(self):
        return self.__suite;


    def run(self):
        unittest.TextTestRunner(verbosity = 2).run(self.__suite);


    @staticmethod
    def fill_suite(unit_cluster_suite):
        unit_cluster_suite.addTests(unittest.TestLoader().loadTestsFromModule(cluster_agglomerative_unit_tests));
        unit_cluster_suite.addTests(unittest.TestLoader().loadTestsFromModule(cluster_birch_unit_tests));
        unit_cluster_suite.addTests(unittest.TestLoader().loadTestsFromModule(cluster_center_initializer_unit_tests));
        unit_cluster_suite.addTests(unittest.TestLoader().loadTestsFromModule(cluster_clarans_unit_tests));
        unit_cluster_suite.addTests(unittest.TestLoader().loadTestsFromModule(cluster_cure_unit_tests));
        unit_cluster_suite.addTests(unittest.TestLoader().loadTestsFromModule(cluster_dbscan_unit_tests));
        unit_cluster_suite.addTests(unittest.TestLoader().loadTestsFromModule(cluster_general_unit_tests));
        unit_cluster_suite.addTests(unittest.TestLoader().loadTestsFromModule(cluster_hsyncnet_unit_tests));
        unit_cluster_suite.addTests(unittest.TestLoader().loadTestsFromModule(cluster_kmeans_unit_tests));
        unit_cluster_suite.addTests(unittest.TestLoader().loadTestsFromModule(cluster_kmedians_unit_tests));
        unit_cluster_suite.addTests(unittest.TestLoader().loadTestsFromModule(cluster_kmedoids_unit_tests));
        unit_cluster_suite.addTests(unittest.TestLoader().loadTestsFromModule(cluster_optics_unit_tests));
        unit_cluster_suite.addTests(unittest.TestLoader().loadTestsFromModule(cluster_rock_unit_tests));
        unit_cluster_suite.addTests(unittest.TestLoader().loadTestsFromModule(cluster_somsc_unit_tests));
        unit_cluster_suite.addTests(unittest.TestLoader().loadTestsFromModule(cluster_syncnet_unit_tests));
        unit_cluster_suite.addTests(unittest.TestLoader().loadTestsFromModule(cluster_syncsom_unit_tests));
        unit_cluster_suite.addTests(unittest.TestLoader().loadTestsFromModule(cluster_xmeans_unit_tests));


if __name__ == "__main__":
    clustering_unit_tests().run();