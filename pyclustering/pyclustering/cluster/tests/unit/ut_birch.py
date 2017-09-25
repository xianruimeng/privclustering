"""!

@brief Unit-tests for BIRCH algorithm.

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

from pyclustering.samples.definitions import SIMPLE_SAMPLES;

from pyclustering.utils import read_sample;

from pyclustering.container.cftree import measurement_type;

from pyclustering.cluster.birch import birch;

from random import random;


class BirchUnitTest(unittest.TestCase):
    def templateClusterAllocation(self, path, cluster_sizes, number_clusters, branching_factor = 5, max_node_entries = 5, initial_diameter = 0.1, type_measurement = measurement_type.CENTROID_EUCLIDIAN_DISTANCE, entry_size_limit = 200, diameter_multiplier = 1.5):
        sample = read_sample(path);
        
        birch_instance = birch(sample, number_clusters, branching_factor, max_node_entries, initial_diameter, type_measurement, entry_size_limit, diameter_multiplier);
        birch_instance.process();
        
        clusters = birch_instance.get_clusters();

        obtained_cluster_sizes = [len(cluster) for cluster in clusters];
        
        total_length = sum(obtained_cluster_sizes);
        assert total_length == len(sample);
        
        if (cluster_sizes != None):
            cluster_sizes.sort();
            obtained_cluster_sizes.sort();
            assert cluster_sizes == obtained_cluster_sizes;


    def testClusterAllocationSampleSimple1CentroidEuclidianDistance(self):
        self.templateClusterAllocation(SIMPLE_SAMPLES.SAMPLE_SIMPLE1, [5, 5], 2, type_measurement = measurement_type.CENTROID_EUCLIDIAN_DISTANCE);
  
    def testClusterAllocationSampleSimple1CentroidManhattanDistance(self):
        self.templateClusterAllocation(SIMPLE_SAMPLES.SAMPLE_SIMPLE1, [5, 5], 2, type_measurement = measurement_type.CENTROID_MANHATTAN_DISTANCE);
  
    def testClusterAllocationSampleSimple1AverageInterClusterDistance(self):
        self.templateClusterAllocation(SIMPLE_SAMPLES.SAMPLE_SIMPLE1, [5, 5], 2, type_measurement = measurement_type.AVERAGE_INTER_CLUSTER_DISTANCE);
  
    def testClusterAllocationSampleSimple1AverageIntraClusterDistance(self):
        self.templateClusterAllocation(SIMPLE_SAMPLES.SAMPLE_SIMPLE1, [5, 5], 2, type_measurement = measurement_type.AVERAGE_INTRA_CLUSTER_DISTANCE);
  
    def testClusterAllocationSampleSimple1VarianceIncreaseDistance(self):
        self.templateClusterAllocation(SIMPLE_SAMPLES.SAMPLE_SIMPLE1, [5, 5], 2, type_measurement = measurement_type.VARIANCE_INCREASE_DISTANCE);
  
    def testClusterAllocationSampleSimple2CentroidEuclidianDistance(self):
        self.templateClusterAllocation(SIMPLE_SAMPLES.SAMPLE_SIMPLE2, [10, 5, 8], 3, type_measurement = measurement_type.CENTROID_EUCLIDIAN_DISTANCE);
  
    def testClusterAllocationSampleSimple2CentroidManhattanDistance(self):
        self.templateClusterAllocation(SIMPLE_SAMPLES.SAMPLE_SIMPLE2, [10, 5, 8], 3, type_measurement = measurement_type.CENTROID_MANHATTAN_DISTANCE);
  
    def testClusterAllocationSampleSimple2AverageInterClusterDistance(self):
        self.templateClusterAllocation(SIMPLE_SAMPLES.SAMPLE_SIMPLE2, [10, 5, 8], 3, type_measurement = measurement_type.AVERAGE_INTER_CLUSTER_DISTANCE);
  
    def testClusterAllocationSampleSimple2AverageIntraClusterDistance(self):
        self.templateClusterAllocation(SIMPLE_SAMPLES.SAMPLE_SIMPLE2, [10, 5, 8], 3, initial_diameter = 1.0, type_measurement = measurement_type.AVERAGE_INTRA_CLUSTER_DISTANCE);
  
    def testClusterAllocationSampleSimple2VarianceIncreaseDistance(self):
        self.templateClusterAllocation(SIMPLE_SAMPLES.SAMPLE_SIMPLE2, [10, 5, 8], 3, type_measurement = measurement_type.VARIANCE_INCREASE_DISTANCE);
  
    def testClusterAllocationSampleSimple3CentroidEuclidianDistance(self):
        self.templateClusterAllocation(SIMPLE_SAMPLES.SAMPLE_SIMPLE3, [10, 10, 10, 30], 4, type_measurement = measurement_type.CENTROID_EUCLIDIAN_DISTANCE);
  
    def testClusterAllocationSampleSimple3CentroidManhattanDistance(self):
        self.templateClusterAllocation(SIMPLE_SAMPLES.SAMPLE_SIMPLE3, [10, 10, 10, 30], 4, type_measurement = measurement_type.CENTROID_MANHATTAN_DISTANCE);

    def testClusterAllocationSampleSimple3AverageInterClusterDistance(self):
        self.templateClusterAllocation(SIMPLE_SAMPLES.SAMPLE_SIMPLE3, [10, 10, 10, 30], 4, initial_diameter = 0.2, max_node_entries = 1, type_measurement = measurement_type.AVERAGE_INTER_CLUSTER_DISTANCE);
 
    def testClusterAllocationSampleSimple3AverageIntraClusterDistance(self):
        self.templateClusterAllocation(SIMPLE_SAMPLES.SAMPLE_SIMPLE3, [10, 10, 10, 30], 4, branching_factor = 4, max_node_entries = 1, initial_diameter = 0.2, type_measurement = measurement_type.AVERAGE_INTRA_CLUSTER_DISTANCE);
 
    def testClusterAllocationSampleSimple3VarianceIncreaseDistance(self):
        self.templateClusterAllocation(SIMPLE_SAMPLES.SAMPLE_SIMPLE3, [10, 10, 10, 30], 4, type_measurement = measurement_type.VARIANCE_INCREASE_DISTANCE);

    def testClusterAllocationSampleSimple4(self):
        self.templateClusterAllocation(SIMPLE_SAMPLES.SAMPLE_SIMPLE4, [15, 15, 15, 15, 15], 5, max_node_entries = 2);
 
    def testClusterAllocationSampleSimple5(self):
        self.templateClusterAllocation(SIMPLE_SAMPLES.SAMPLE_SIMPLE5, [15, 15, 15, 15], 4);
 
    def testClusterAllocationSampleSimple7(self):
        self.templateClusterAllocation(SIMPLE_SAMPLES.SAMPLE_SIMPLE7, [10, 10], 2);

    def testClusterAllocationSampleSimple8(self):
        self.templateClusterAllocation(SIMPLE_SAMPLES.SAMPLE_SIMPLE8, [15, 30, 20, 80], 4, max_node_entries = 2);

    def templateClusterAllocationOneDimensionData(self, branching_factor = 5, max_node_entries = 10, initial_diameter = 1.0, type_measurement = measurement_type.CENTROID_EUCLIDIAN_DISTANCE, entry_size_limit = 20):
        input_data = [ [random()] for _ in range(10) ] + [ [random() + 4] for _ in range(10) ] + [ [random() + 8] for _ in range(10) ] + [ [random() + 12] for _ in range(10) ];
         
        birch_instance = birch(input_data, 4, branching_factor, max_node_entries, initial_diameter, type_measurement, entry_size_limit);
        birch_instance.process();
        clusters = birch_instance.get_clusters();
         
        assert len(clusters) == 4;
        for cluster in clusters:
            assert len(cluster) == 10;
 
    def testClusterAllocationOneDimensionCentroidEuclidianDistance(self):
        self.templateClusterAllocationOneDimensionData(type_measurement = measurement_type.CENTROID_EUCLIDIAN_DISTANCE);
 
    def testClusterAllocationOneDimensionCentroidManhattanDistance(self):
        self.templateClusterAllocationOneDimensionData(type_measurement = measurement_type.CENTROID_MANHATTAN_DISTANCE);
 
    def testClusterAllocationOneAverageInterClusterDistance(self):
        self.templateClusterAllocationOneDimensionData(type_measurement = measurement_type.AVERAGE_INTER_CLUSTER_DISTANCE);
 
    def testClusterAllocationOneAverageIntraClusterDistance(self):
        self.templateClusterAllocationOneDimensionData(type_measurement = measurement_type.AVERAGE_INTRA_CLUSTER_DISTANCE);
 
    def testClusterAllocationOneVarianceIncreaseDistance(self):
        self.templateClusterAllocationOneDimensionData(type_measurement = measurement_type.VARIANCE_INCREASE_DISTANCE);


if __name__ == "__main__":
    unittest.main();