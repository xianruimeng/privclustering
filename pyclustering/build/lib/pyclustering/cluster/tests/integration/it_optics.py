"""!

@brief Integration-tests for OPTICS algorithm.

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

from pyclustering.cluster.tests.optics_templates import OpticsTestTemplates;
from pyclustering.cluster.optics import optics;

from pyclustering.samples.definitions import SIMPLE_SAMPLES, FCPS_SAMPLES;


class OpticsIntegrationTest(unittest.TestCase):
    def testClusteringSampleSimple1ByCore(self):
        OpticsTestTemplates.templateClusteringResults(SIMPLE_SAMPLES.SAMPLE_SIMPLE1, 0.4, 2, None, [5, 5], True);

    def testClusteringSampleSimple2ByCore(self):
        OpticsTestTemplates.templateClusteringResults(SIMPLE_SAMPLES.SAMPLE_SIMPLE2, 1, 2, None, [5, 8, 10], True);

    def testClusteringSampleSimple3ByCore(self):
        OpticsTestTemplates.templateClusteringResults(SIMPLE_SAMPLES.SAMPLE_SIMPLE3, 0.7, 3, None, [10, 10, 10, 30], True);

    def testClusteringSampleSimple4ByCore(self):
        OpticsTestTemplates.templateClusteringResults(SIMPLE_SAMPLES.SAMPLE_SIMPLE4, 0.7, 3, None, [15, 15, 15, 15, 15], True);

    def testClusteringSampleSimple5ByCore(self):
        OpticsTestTemplates.templateClusteringResults(SIMPLE_SAMPLES.SAMPLE_SIMPLE5, 0.7, 3, None, [15, 15, 15, 15], True);

    def testClusteringHeptaByCore(self):
        OpticsTestTemplates.templateClusteringResults(FCPS_SAMPLES.SAMPLE_HEPTA, 1, 3, None, [30, 30, 30, 30, 30, 30, 32], True);

    def testClusteringOneDimensionDataSampleSimple9ByCore(self):
        OpticsTestTemplates.templateClusteringResults(SIMPLE_SAMPLES.SAMPLE_SIMPLE9, 3.0, 3, None, [10, 20], True);

    def testClusteringSampleSimple2RadiusGreaterByCore(self):
        OpticsTestTemplates.templateClusteringResults(SIMPLE_SAMPLES.SAMPLE_SIMPLE2, 5.0, 2, 3, [5, 8, 10], True);

    def testClusteringSampleSimple3RadiusGreaterByCore(self):
        OpticsTestTemplates.templateClusteringResults(SIMPLE_SAMPLES.SAMPLE_SIMPLE3, 5.0, 3, 4, [10, 10, 10, 30], True);

    def testClusteringSampleSimple4RadiusGreaterByCore(self):
        OpticsTestTemplates.templateClusteringResults(SIMPLE_SAMPLES.SAMPLE_SIMPLE4, 6.0, 3, 5, [15, 15, 15, 15, 15], True);

    def testClusteringLsunRadiusGreaterByCore(self):
        OpticsTestTemplates.templateClusteringResults(FCPS_SAMPLES.SAMPLE_LSUN, 1.0, 3, 3, [99, 100, 202], True);


    def testCoreInterfaceIntInputData(self):
        optics_instance = optics([ [1], [2], [3], [20], [21], [22] ], 3, 2, 2, True);
        optics_instance.process();
        assert len(optics_instance.get_clusters()) == 2;


if __name__ == "__main__":
    unittest.main();