"""!

@brief Unit-tests for OPTICS algorithm.

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
from pyclustering.cluster.optics import optics, ordering_analyser, ordering_visualizer;

from pyclustering.utils import read_sample;

from pyclustering.samples.definitions import SIMPLE_SAMPLES, FCPS_SAMPLES;


class OpticsUnitTest(unittest.TestCase):
    def testClusteringSampleSimple1(self):
        OpticsTestTemplates.templateClusteringResults(SIMPLE_SAMPLES.SAMPLE_SIMPLE1, 0.4, 2, None, [5, 5], False);

    def testClusteringSampleSimple2(self):
        OpticsTestTemplates.templateClusteringResults(SIMPLE_SAMPLES.SAMPLE_SIMPLE2, 1, 2, None, [5, 8, 10], False);

    def testClusteringSampleSimple3(self):
        OpticsTestTemplates.templateClusteringResults(SIMPLE_SAMPLES.SAMPLE_SIMPLE3, 0.7, 3, None, [10, 10, 10, 30], False);

    def testClusteringSampleSimple4(self):
        OpticsTestTemplates.templateClusteringResults(SIMPLE_SAMPLES.SAMPLE_SIMPLE4, 0.7, 3, None, [15, 15, 15, 15, 15], False);

    def testClusteringSampleSimple5(self):
        OpticsTestTemplates.templateClusteringResults(SIMPLE_SAMPLES.SAMPLE_SIMPLE5, 0.7, 3, None, [15, 15, 15, 15], False);

    def testClusteringHepta(self):
        OpticsTestTemplates.templateClusteringResults(FCPS_SAMPLES.SAMPLE_HEPTA, 1, 3, None, [30, 30, 30, 30, 30, 30, 32], False);
  
    def testClusteringOneDimensionDataSampleSimple7(self):
        OpticsTestTemplates.templateClusteringResults(SIMPLE_SAMPLES.SAMPLE_SIMPLE7, 2.0, 2, None, [10, 10], False);

    def testClusteringOneDimensionDataSampleSimple9(self):
        OpticsTestTemplates.templateClusteringResults(SIMPLE_SAMPLES.SAMPLE_SIMPLE9, 3.0, 3, None, [10, 20], False);

    def testClusteringSampleSimple2RadiusGreater(self):
        OpticsTestTemplates.templateClusteringResults(SIMPLE_SAMPLES.SAMPLE_SIMPLE2, 5.0, 2, 3, [5, 8, 10], False);

    def testClusteringSampleSimple3RadiusGreater(self):
        OpticsTestTemplates.templateClusteringResults(SIMPLE_SAMPLES.SAMPLE_SIMPLE3, 5.0, 3, 4, [10, 10, 10, 30], False);

    def testClusteringSampleSimple4RadiusGreater(self):
        OpticsTestTemplates.templateClusteringResults(SIMPLE_SAMPLES.SAMPLE_SIMPLE4, 6.0, 3, 5, [15, 15, 15, 15, 15], False);

    def testClusteringLsunRadiusGreater(self):
        OpticsTestTemplates.templateClusteringResults(FCPS_SAMPLES.SAMPLE_LSUN, 1.0, 3, 3, [99, 100, 202], False);

    def testClusteringOrderVisualizer(self):
        sample = read_sample(SIMPLE_SAMPLES.SAMPLE_SIMPLE4);
           
        optics_instance = optics(sample, 6.0, 3, 5);
        optics_instance.process();
           
        analyser = ordering_analyser(optics_instance.get_ordering());
        ordering_visualizer.show_ordering_diagram(analyser, 5);

    def testClusterOrderingOneClusterExtraction(self):
        analyser = ordering_analyser([5.0, 5.0, 5.0, 5.0, 5.0, 5.0]);
        
        amount_clusters, borders = analyser.extract_cluster_amount(6.5);
        assert 1 == amount_clusters;
        assert 0 == len(borders);
        
        amount_clusters, borders = analyser.extract_cluster_amount(4.5);
        assert 0 == amount_clusters;
        assert 0 == len(borders);

    def testImpossibleClusterOrderingAllocationHomogeneous(self):
        analyser = ordering_analyser([5.0, 5.0, 5.0, 5.0, 5.0, 5.0, 5.0, 5.0, 5.0, 5.0]);
        amount_clusters, borders = analyser.calculate_connvectivity_radius(2);
        assert None == amount_clusters;
        assert 0 == len(borders);

    def testImpossibleClusterOrderingAllocationGeterogeneous(self):
        analyser = ordering_analyser([5.0, 5.0, 5.0, 5.0, 6.0, 8.0, 6.0, 5.0, 5.0, 5.0]);
        amount_clusters, borders = analyser.calculate_connvectivity_radius(3);
        assert None == amount_clusters;
        assert 0 == len(borders);


if __name__ == "__main__":
    unittest.main();