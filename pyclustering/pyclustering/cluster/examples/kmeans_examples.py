"""!

@brief Examples of usage and demonstration of abilities of K-Means algorithm in cluster analysis.

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

from pyclustering.samples.definitions import SIMPLE_SAMPLES, FCPS_SAMPLES;

from pyclustering.cluster import cluster_visualizer;
from pyclustering.cluster.kmeans import kmeans;

from pyclustering.utils import read_sample;
from pyclustering.utils import timedcall;

def template_clustering(start_centers, path, tolerance = 0.25, ccore = True):
    sample = read_sample(path);
    
    kmeans_instance = kmeans(sample, start_centers, tolerance, ccore);
    (ticks, result) = timedcall(kmeans_instance.process);
    
    clusters = kmeans_instance.get_clusters();
    centers = kmeans_instance.get_centers();
    
    print("Sample: ", path, "\t\tExecution time: ", ticks, "\n");

    visualizer = cluster_visualizer();
    visualizer.append_clusters(clusters, sample);
    visualizer.append_cluster(start_centers, marker = '*', markersize = 15);
    visualizer.append_cluster(centers, marker = '*', markersize = 15);
    visualizer.show();
    
    
def cluster_sample1():
    start_centers = [[4.7, 5.9], [5.7, 6.5]];
    template_clustering(start_centers, SIMPLE_SAMPLES.SAMPLE_SIMPLE1);
    
def cluster_sample2():
    start_centers = [[3.5, 4.8], [6.9, 7], [7.5, 0.5]];
    template_clustering(start_centers, SIMPLE_SAMPLES.SAMPLE_SIMPLE2);
    
def cluster_sample3():
    start_centers = [[0.2, 0.1], [4.0, 1.0], [2.0, 2.0], [2.3, 3.9]];
    template_clustering(start_centers, SIMPLE_SAMPLES.SAMPLE_SIMPLE3);
    
def cluster_sample4():
    start_centers = [[1.5, 0.0], [1.5, 2.0], [1.5, 4.0], [1.5, 6.0], [1.5, 8.0]];
    template_clustering(start_centers, SIMPLE_SAMPLES.SAMPLE_SIMPLE4);
    
def cluster_sample5():
    start_centers = [[0.0, 1.0], [0.0, 0.0], [1.0, 1.0], [1.0, 0.0]];
    template_clustering(start_centers, SIMPLE_SAMPLES.SAMPLE_SIMPLE5);

def cluster_sample7():
    start_centers = [[-3.0], [2.5]];
    template_clustering(start_centers, SIMPLE_SAMPLES.SAMPLE_SIMPLE7);

def cluster_sample8():
    start_centers = [[-4.0], [3.1], [6.1], [12.0]];
    template_clustering(start_centers, SIMPLE_SAMPLES.SAMPLE_SIMPLE8);

def cluster_elongate():
    "Not so applicable for this sample"
    start_centers = [[1.0, 4.5], [3.1, 2.7]];
    template_clustering(start_centers, SIMPLE_SAMPLES.SAMPLE_ELONGATE);

def cluster_lsun():
    "Not so applicable for this sample"
    start_centers = [[1.0, 3.5], [2.0, 0.5], [3.0, 3.0]];
    template_clustering(start_centers, FCPS_SAMPLES.SAMPLE_LSUN);
    
def cluster_target():
    "Not so applicable for this sample"
    start_centers = [[0.2, 0.2], [0.0, -2.0], [3.0, -3.0], [3.0, 3.0], [-3.0, 3.0], [-3.0, -3.0]];
    template_clustering(start_centers, FCPS_SAMPLES.SAMPLE_TARGET);

def cluster_two_diamonds():
    start_centers = [[0.8, 0.2], [3.0, 0.0]];
    template_clustering(start_centers, FCPS_SAMPLES.SAMPLE_TWO_DIAMONDS);

def cluster_wing_nut():
    "Almost good!"
    start_centers = [[-1.5, 1.5], [1.5, 1.5]];
    template_clustering(start_centers, FCPS_SAMPLES.SAMPLE_WING_NUT); 
    
def cluster_chainlink():
    start_centers = [[1.1, -1.7, 1.1], [-1.4, 2.5, -1.2]];
    template_clustering(start_centers, FCPS_SAMPLES.SAMPLE_CHAINLINK);
    
def cluster_hepta():
    start_centers = [[0.0, 0.0, 0.0], [3.0, 0.0, 0.0], [-2.0, 0.0, 0.0], [0.0, 3.0, 0.0], [0.0, -3.0, 0.0], [0.0, 0.0, 2.5], [0.0, 0.0, -2.5]];
    template_clustering(start_centers, FCPS_SAMPLES.SAMPLE_HEPTA); 
    
def cluster_tetra():
    start_centers = [[1, 0, 0], [0, 1, 0], [0, -1, 0], [-1, 0, 0]];
    template_clustering(start_centers, FCPS_SAMPLES.SAMPLE_TETRA);
    
def cluster_engy_time():
    start_centers = [[0.5, 0.5], [2.3, 2.9]];
    template_clustering(start_centers, FCPS_SAMPLES.SAMPLE_ENGY_TIME);
    
def experiment_execution_time(ccore = False):
    template_clustering([[3.7, 5.5], [6.7, 7.5]], SIMPLE_SAMPLES.SAMPLE_SIMPLE1, ccore);
    template_clustering([[3.5, 4.8], [6.9, 7], [7.5, 0.5]], SIMPLE_SAMPLES.SAMPLE_SIMPLE2, ccore);
    template_clustering([[0.2, 0.1], [4.0, 1.0], [2.0, 2.0], [2.3, 3.9]], SIMPLE_SAMPLES.SAMPLE_SIMPLE3, ccore);
    template_clustering([[1.5, 0.0], [1.5, 2.0], [1.5, 4.0], [1.5, 6.0], [1.5, 8.0]], SIMPLE_SAMPLES.SAMPLE_SIMPLE4, ccore);
    template_clustering([[0.0, 1.0], [0.0, 0.0], [1.0, 1.0], [1.0, 0.0]], SIMPLE_SAMPLES.SAMPLE_SIMPLE5, ccore);
    template_clustering([[1.0, 4.5], [3.1, 2.7]], SIMPLE_SAMPLES.SAMPLE_ELONGATE, ccore);
    template_clustering([[1.0, 3.5], [2.0, 0.5], [3.0, 3.0]], FCPS_SAMPLES.SAMPLE_LSUN, ccore);
    template_clustering([[0.2, 0.2], [0.0, -2.0], [3.0, -3.0], [3.0, 3.0], [-3.0, 3.0], [-3.0, -3.0]], FCPS_SAMPLES.SAMPLE_TARGET, ccore);
    template_clustering([[0.8, 0.2], [3.0, 0.0]], FCPS_SAMPLES.SAMPLE_TWO_DIAMONDS, ccore);  
    template_clustering([[-1.5, 1.5], [1.5, 1.5]], FCPS_SAMPLES.SAMPLE_WING_NUT, ccore); 
    template_clustering([[1.1, -1.7, 1.1], [-1.4, 2.5, -1.2]], FCPS_SAMPLES.SAMPLE_CHAINLINK, ccore);  
    template_clustering([[0.0, 0.0, 0.0], [3.0, 0.0, 0.0], [-2.0, 0.0, 0.0], [0.0, 3.0, 0.0], [0.0, -3.0, 0.0], [0.0, 0.0, 2.5], [0.0, 0.0, -2.5]], FCPS_SAMPLES.SAMPLE_HEPTA, ccore); 
    template_clustering([[1, 0, 0], [0, 1, 0], [0, -1, 0], [-1, 0, 0]], FCPS_SAMPLES.SAMPLE_TETRA, ccore);
    template_clustering([[-0.5, -0.5, -0.5], [0.5, 0.5, 0.5]], FCPS_SAMPLES.SAMPLE_ATOM, ccore);
    template_clustering([[0.5, 0.5], [2.3, 2.9]], FCPS_SAMPLES.SAMPLE_ENGY_TIME, ccore);


cluster_sample1();
cluster_sample2();
cluster_sample3();
cluster_sample4();
cluster_sample5();
cluster_sample7();
cluster_sample8();
cluster_elongate();
cluster_lsun();
cluster_target();
cluster_two_diamonds();
cluster_wing_nut();
cluster_chainlink();
cluster_hepta();
cluster_tetra();
cluster_engy_time();
  
experiment_execution_time(False);   # Python code
experiment_execution_time(True);    # C++ code + Python env.
