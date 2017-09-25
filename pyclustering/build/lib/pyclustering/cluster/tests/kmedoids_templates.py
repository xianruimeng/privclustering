"""!

@brief Test templates for K-Medoids clustering module.

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


import math;

from pyclustering.cluster.kmedoids import kmedoids;

from pyclustering.utils import read_sample;

from random import random;


class KmedoidsTestTemplates:
    @staticmethod
    def templateLengthProcessData(path_to_file, initial_medoids, expected_cluster_length, ccore_flag = False):
        sample = read_sample(path_to_file);
         
        kmedoids_instance = kmedoids(sample, initial_medoids, 0.025, ccore_flag);
        kmedoids_instance.process();
         
        clusters = kmedoids_instance.get_clusters();
     
        obtained_cluster_sizes = [len(cluster) for cluster in clusters];
        assert len(sample) == sum(obtained_cluster_sizes);
         
        obtained_cluster_sizes.sort();
        expected_cluster_length.sort();
        assert obtained_cluster_sizes == expected_cluster_length;


    @staticmethod
    def templateClusterAllocationOneDimensionData():
        input_data = [ [random()] for i in range(10) ] + [ [random() + 3] for i in range(10) ] + [ [random() + 5] for i in range(10) ] + [ [random() + 8] for i in range(10) ];
         
        kmedoids_instance = kmedoids(input_data, [ 5, 15, 25, 35 ], 0.025);
        kmedoids_instance.process();
        clusters = kmedoids_instance.get_clusters();
         
        assert len(clusters) == 4;
        for cluster in clusters:
            assert len(cluster) == 10;


    @staticmethod
    def templateClusterAllocationTheSameObjects(number_objects, number_clusters, ccore_flag = False):
        value = random();
        input_data = [ [value] ] * number_objects;
        
        initial_medoids = [];
        step = math.floor(number_objects / number_clusters);
        for i in range(number_clusters):
            initial_medoids.append(i * step);
        
        kmedoids_instance = kmedoids(input_data, initial_medoids);
        kmedoids_instance.process();
        clusters = kmedoids_instance.get_clusters();
        
        object_mark = [False] * number_objects;
        allocated_number_objects = 0;
        
        for cluster in clusters:
            for index_object in cluster: 
                assert (object_mark[index_object] == False);    # one object can be in only one cluster.
                
                object_mark[index_object] = True;
                allocated_number_objects += 1;
            
        assert (number_objects == allocated_number_objects);    # number of allocated objects should be the same.