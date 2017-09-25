"""!

@brief Integration-test runner for tests of clustering algorithms.

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


from pyclustering.cluster.tests.integration               import it_agglomerative as cluster_agglomerative_integration_tests;
from pyclustering.cluster.tests.integration               import it_antmean       as cluster_antmean_integration_tests;
from pyclustering.cluster.tests.integration               import it_cure          as cluster_cure_integration_tests;
from pyclustering.cluster.tests.integration               import it_dbscan        as cluster_dbscan_integration_tests;
from pyclustering.cluster.tests.integration               import it_hsyncnet      as cluster_hsyncnet_integration_tests;
from pyclustering.cluster.tests.integration               import it_kmeans        as cluster_kmeans_integration_tests;
from pyclustering.cluster.tests.integration               import it_kmedians      as cluster_kmedians_integration_tests;
from pyclustering.cluster.tests.integration               import it_kmedoids      as cluster_kmedoids_integration_tests;
from pyclustering.cluster.tests.integration               import it_optics        as cluster_optics_integration_tests;
from pyclustering.cluster.tests.integration               import it_rock          as cluster_rock_integration_tests;
from pyclustering.cluster.tests.integration               import it_somsc         as cluster_somsc_integration_tests;
from pyclustering.cluster.tests.integration               import it_syncnet       as cluster_syncnet_integration_tests;
from pyclustering.cluster.tests.integration               import it_xmeans        as cluster_xmeans_integration_tests;


class clustering_integration_tests:
    def __init__(self):
        self.__suite = unittest.TestSuite();
        self.fill_suite(self.__suite);


    def get_suite(self):
        return self.__suite;


    def run(self):
        unittest.TextTestRunner(verbosity = 2).run(self.__suite);


    @staticmethod
    def fill_suite(integration_cluster_suite):
        integration_cluster_suite.addTests(unittest.TestLoader().loadTestsFromModule(cluster_agglomerative_integration_tests));
        integration_cluster_suite.addTests(unittest.TestLoader().loadTestsFromModule(cluster_antmean_integration_tests));
        integration_cluster_suite.addTests(unittest.TestLoader().loadTestsFromModule(cluster_cure_integration_tests));
        integration_cluster_suite.addTests(unittest.TestLoader().loadTestsFromModule(cluster_dbscan_integration_tests));
        integration_cluster_suite.addTests(unittest.TestLoader().loadTestsFromModule(cluster_hsyncnet_integration_tests));
        integration_cluster_suite.addTests(unittest.TestLoader().loadTestsFromModule(cluster_kmeans_integration_tests));
        integration_cluster_suite.addTests(unittest.TestLoader().loadTestsFromModule(cluster_kmedians_integration_tests));
        integration_cluster_suite.addTests(unittest.TestLoader().loadTestsFromModule(cluster_kmedoids_integration_tests));
        integration_cluster_suite.addTests(unittest.TestLoader().loadTestsFromModule(cluster_optics_integration_tests));
        integration_cluster_suite.addTests(unittest.TestLoader().loadTestsFromModule(cluster_rock_integration_tests));
        integration_cluster_suite.addTests(unittest.TestLoader().loadTestsFromModule(cluster_somsc_integration_tests));
        integration_cluster_suite.addTests(unittest.TestLoader().loadTestsFromModule(cluster_syncnet_integration_tests));
        integration_cluster_suite.addTests(unittest.TestLoader().loadTestsFromModule(cluster_xmeans_integration_tests));


if __name__ == "__main__":
    clustering_integration_tests().run();
