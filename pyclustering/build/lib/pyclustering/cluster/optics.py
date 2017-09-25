"""!

@brief Cluster analysis algorithm: OPTICS (Ordering Points To Identify Clustering Structure)
@details Based on article description:
         - M.Ankerst, M.Breunig, H.Kriegel, J.Sander. OPTICS: Ordering Points To Identify the Clustering Structure. 1999.

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


from pyclustering.cluster.encoder import type_encoding;

from pyclustering.utils import euclidean_distance;
from pyclustering.utils.color import color as color_list;

import matplotlib.pyplot as plt;

import pyclustering.core.optics_wrapper as wrapper;


class ordering_visualizer:
    """!
    @brief Cluster ordering diagram visualizer that represents dataset graphically as density-based clustering structure.
    
    @see ordering_analyser
    
    """
    
    @staticmethod
    def show_ordering_diagram(analyser, amount_clusters = None):
        """!
        @brief Display cluster-ordering (reachability-plot) diagram.
        
        @param[in] analyser (ordering_analyser): cluster-ordering analyser whose ordering diagram should be displayed.
        @param[in] amount_clusters (uint): if it is not 'None' then it displays connectivity radius line that can used for allocation of specified amount of clusters
                    and colorize diagram by corresponding cluster colors.
        
        Example demonstrates general abilities of 'ordering_visualizer' class:
        @code
        # Display cluster-ordering diagram with connectivity radius is used for allocation of three clusters.
        ordering_visualizer.show_ordering_diagram(analyser, 3);
        
        # Display cluster-ordering diagram without radius.
        ordering_visualizer.show_ordering_diagram(analyser);
        @endcode
        
        """
        ordering = analyser.cluster_ordering;
        axis = plt.subplot(111);
        
        if (amount_clusters is not None):
            radius, borders = analyser.calculate_connvectivity_radius(amount_clusters);
        
            # divide into cluster groups to visualize by colors
            left_index_border = 0;
            current_index_border = 0;
            for index_border in range(len(borders)):
                right_index_border = borders[index_border];
                axis.bar(range(left_index_border, right_index_border), ordering[left_index_border:right_index_border], width = 1.0, color = color_list.TITLES[index_border]);
                left_index_border = right_index_border;
                current_index_border = index_border;
            
            axis.bar(range(left_index_border, len(ordering)), ordering[left_index_border:len(ordering)], width = 1.0, color = color_list.TITLES[current_index_border + 1]);
            
            plt.xlim([0, len(ordering)]);
            
            plt.axhline(y = radius, linewidth = 2, color = 'black');
            plt.text(0, radius + radius * 0.03, " Radius:   " + str(round(radius, 4)) + ";\n Clusters: " + str(amount_clusters), color = 'b', fontsize = 10);
            
        else:
            axis.bar(range(0, len(ordering)), ordering[0:len(ordering)], width = 1.0, color = 'black');
            plt.xlim([0, len(ordering)]);
        
        plt.show();


class ordering_analyser:
    """!
    @brief Analyser of cluster ordering diagram.
    @details Using cluster-ordering it is able to connectivity radius for allocation of specified amount of clusters and
              calculate amount of clusters using specified connectivity radius. Cluster-ordering is formed by OPTICS algorithm
              during cluster analysis.
    
    @see optics
    
    """
    
    @property
    def cluster_ordering(self):
        """!
        @brief (list) Returns values of dataset cluster ordering.
        
        """
        return self.__ordering;
    
    
    def __init__(self, ordering_diagram):
        """!
        @brief Analyser of ordering diagram that is based on reachability-distances.
        
        @see calculate_connvectivity_radius
        
        """
        self.__ordering = ordering_diagram;
    
    
    def __len__(self):
        """!
        @brief Returns length of clustering-ordering diagram.
        
        """
        return len(self.__ordering);
    
    
    def calculate_connvectivity_radius(self, amount_clusters, maximum_iterations = 100):
        """!
        @brief Calculates connectivity radius of allocation specified amount of clusters using ordering diagram and marks borders of clusters using indexes of values of ordering diagram.
        @details Parameter 'maximum_iterations' is used to protect from hanging when it is impossible to allocate specified number of clusters.
        
        @param[in] amount_clusters (uint): amount of clusters that should be allocated by calculated connectivity radius.
        @param[in] maximum_iterations (uint): maximum number of iteration for searching connectivity radius to allocated specified amount of clusters (by default it is restricted by 100 iterations).
        
        @return (double, list) Value of connectivity radius and borders of clusters like (radius, borders), radius may be 'None' as well as borders may be '[]'
                                if connectivity radius hasn't been found for the specified amount of iterations.
        
        """
        
        maximum_distance = max(self.__ordering);
        
        upper_distance = maximum_distance;
        lower_distance = 0.0;
        
        radius = None;
        result = None;
        
        amount, borders = self.extract_cluster_amount(maximum_distance);
        if (amount <= amount_clusters):
            for _ in range(maximum_iterations):
                radius = (lower_distance + upper_distance) / 2.0;
                
                amount, borders = self.extract_cluster_amount(radius);
                if (amount == amount_clusters):
                    result = radius;
                    break;
                
                elif (amount == 0):
                    break;
                
                elif (amount > amount_clusters):
                    lower_distance = radius;
                
                elif (amount < amount_clusters):
                    upper_distance = radius;
        
        return result, borders;
    
    
    def extract_cluster_amount(self, radius):
        """!
        @brief Obtains amount of clustering that can be allocated by using specified radius for ordering diagram and borders between them.
        @details When growth of reachability-distances is detected than it is considered as a start point of cluster, 
                 than pick is detected and after that recession is observed until new growth (that means end of the
                 current cluster and start of a new one) or end of diagram.
        
        @param[in] radius (double): connectivity radius that is used for cluster allocation.
        
        @return (unit, list) Amount of clusters that can be allocated by the connectivity radius on ordering diagram and borders between them using indexes
                 from ordering diagram (amount_clusters, border_clusters).
        
        """
        
        amount_clusters = 1;
        
        cluster_start = False;
        cluster_pick = False;
        total_similarity = True;
        previous_cluster_distance = None;
        previous_distance = None;
        
        cluster_borders = [];
        
        for index_ordering in range(len(self.__ordering)):
            distance = self.__ordering[index_ordering];
            if (distance >= radius):
                if (cluster_start is False):
                    cluster_start = True;
                    amount_clusters += 1;
                    
                    if (index_ordering != 0):
                        cluster_borders.append(index_ordering);
                
                else:
                    if ((distance < previous_cluster_distance) and (cluster_pick is False)):
                        cluster_pick = True;
                    
                    elif ((distance > previous_cluster_distance) and (cluster_pick is True)):
                        cluster_pick = False;
                        amount_clusters += 1;
                        
                        if (index_ordering != 0):
                            cluster_borders.append(index_ordering);
                
                previous_cluster_distance = distance;
            
            else:
                cluster_start = False;
                cluster_pick = False;
            
            if ( (previous_distance is not None) and (distance != previous_distance) ):
                total_similarity = False;
            
            previous_distance = distance;
        
        if ( (total_similarity is True) and (previous_distance > radius) ):
            amount_clusters = 0;

        return amount_clusters, cluster_borders;


class optics_descriptor:
    """!
    @brief Object description that used by OPTICS algorithm for cluster analysis.
    
    """

    def __init__(self, index, core_distance = None, reachability_distance = None):
        """!
        @brief Constructor of object description in optics terms.
        
        @param[in] index (uint): Index of the object in the data set.
        @param[in] core_distance (double): Core distance that is minimum distance to specified number of neighbors.
        @param[in] reachability_distance (double): Reachability distance to this object.
        
        """
        
        ## Reachability distance - the smallest distance to be reachable by core object.
        self.index_object = index;
        
        ## Core distance - the smallest distance to reach specified number of neighbors that is not greater then connectivity radius.
        self.core_distance = core_distance;
        
        ## Index of object from the input data.
        self.reachability_distance = reachability_distance;
        
        ## True is object has been already traversed.
        self.processed = False;

    def __repr__(self):
        """!
        @brief Returns string representation of the optics descriptor.
        
        """
        
        return '(%s, [c: %s, r: %s])' % (self.index_object, self.core_distance, self.reachability_distance);


class optics:
    """!
    @brief Class represents clustering algorithm OPTICS (Ordering Points To Identify Clustering Structure).
    @details OPTICS is a density-based algorithm. Purpose of the algorithm is to provide explicit clusters, but create clustering-ordering representation of the input data. 
             Clustering-ordering information contains information about internal structures of data set in terms of density and proper connectivity radius can be obtained
             for allocation required amount of clusters using this diagram. In case of usage additional input parameter 'amount of clusters' connectivity radius should be
             bigger than real - because it will be calculated by the algorithms if requested amount of clusters is not allocated.

    @image html optics_example_clustering.png "Scheme how does OPTICS works. At the beginning only one cluster is allocated, but two is requested. At the second step OPTICS calculates connectivity radius using cluster-ordering and performs final cluster allocation."

    Example:
    @code
        # Read sample for clustering from some file
        sample = read_sample(path_sample);
        
        # Create OPTICS algorithm for cluster analysis
        optics_instance = optics(sample, 0.5, 6);
        
        # Run cluster analysis
        optics_instance.process();
        
        # Obtain results of clustering
        clusters = optics_instance.get_clusters();
        noise = optics_instance.get_noise();
        
        # Obtain rechability-distances
        ordering = ordering_analyser(optics_instance.get_ordering());
        
        # Visualization of cluster ordering in line with reachability distance.
        ordering_visualizer.show_ordering_diagram(ordering);
    @endcode
    
    Amount of clusters that should be allocated can be also specified. In this case connectivity radius should be greater than real, for example:
    @code
        # Import required packages
        from pyclustering.cluster.optics import optics;
        from pyclustering.samples.definitions import FCPS_SAMPLES;
        from pyclustering.utils import read_sample;
        
        # Read sample for clustering from some file
        sample = read_sample(FCPS_SAMPLES.SAMPLE_LSUN);
        
        # Run cluster analysis where connvectivity radius is bigger than real
        radius = 2.0;
        neighbors = 3;
        amount_of_clusters = 3;
        
        optics_instance = optics(sample, radius, neighbors, amount_of_clusters);
        
        # Obtain results of clustering
        clusters = optics_instance.get_clusters();
        noise = optics_instance.get_noise();
    @endcode
    
    """
    
    def __init__(self, sample, eps, minpts, amount_clusters = None, ccore = False):
        """!
        @brief Constructor of clustering algorithm OPTICS.
        
        @param[in] sample (list): Input data that is presented as a list of points (objects), where each point is represented by list or tuple.
        @param[in] eps (double): Connectivity radius between points, points may be connected if distance between them less than the radius.
        @param[in] minpts (uint): Minimum number of shared neighbors that is required for establishing links between points.
        @param[in] amount_clusters (uint): Optional parameter where amount of clusters that should be allocated is specified.
                    In case of usage 'amount_clusters' connectivity radius can be greater than real, in other words, there is place for mistake
                    in connectivity radius usage.
        @param[in] ccore (bool): if True than DLL CCORE (C++ solution) will be used for solving the problem.
        
        """
        
        self.__sample_pointer = sample;     # Algorithm parameter - pointer to sample for processing.
        self.__eps = eps;                   # Algorithm parameter - connectivity radius between object for establish links between object.
        self.__minpts = minpts;             # Algorithm parameter - minimum number of neighbors that is required for establish links between object.
        self.__amount_clusters = amount_clusters;
        
        self.__ordering = None;
        self.__clusters = None;
        self.__noise = None;
        
        self.__ccore = ccore;


    def process(self):
        """!
        @brief Performs cluster analysis in line with rules of OPTICS algorithm.
        
        @remark Results of clustering can be obtained using corresponding gets methods.
        
        @see get_clusters()
        @see get_noise()
        @see get_ordering()
        
        """
        
        if (self.__ccore is True):
            (self.__clusters, self.__noise, self.__ordering, self.__eps) = wrapper.optics(self.__sample_pointer, self.__eps, self.__minpts, self.__amount_clusters);
        
        else:
            self.__allocate_clusters();
            
            if ( (self.__amount_clusters is not None) and (self.__amount_clusters != len(self.get_clusters())) ):
                analyser = ordering_analyser(self.get_ordering());
                radius, _ = analyser.calculate_connvectivity_radius(self.__amount_clusters);
                if (radius is not None):
                    self.__eps = radius;
                    self.__allocate_clusters();


    def __initialize(self, sample):
        """!
        @brief Initializes internal states and resets clustering results in line with input sample.
        
        """
        
        self.__processed = [False] * len(sample);
        self.__optics_objects = [optics_descriptor(i) for i in range(len(sample))];     # List of OPTICS objects that corresponds to objects from input sample.
        self.__ordered_database = [];       # List of OPTICS objects in traverse order. 
        
        self.__clusters = None;     # Result of clustering (list of clusters where each cluster contains indexes of objects from input data).
        self.__noise = None;        # Result of clustering (noise).


    def __allocate_clusters(self):
        """!
        @brief Performs cluster allocation and builds ordering diagram that is based on reachability-distances.
        
        """
        
        self.__initialize(self.__sample_pointer);
        
        for optic_object in self.__optics_objects:
            if (optic_object.processed is False):
                self.__expand_cluster_order(optic_object);
        
        self.__extract_clusters();
    
    
    def get_clusters(self):
        """!
        @brief Returns list of allocated clusters, where each cluster contains indexes of objects and each cluster is represented by list.
        
        @return (list) List of allocated clusters.
        
        @see process()
        @see get_noise()
        @see get_ordering()
        @see get_radius()
        
        """
        
        return self.__clusters;
    
    
    def get_noise(self):
        """!
        @brief Returns list of noise that contains indexes of objects that corresponds to input data.
        
        @return (list) List of allocated noise objects.
        
        @see process()
        @see get_clusters()
        @see get_ordering()
        @see get_radius()
        
        """
        
        return self.__noise;
    
    
    def get_ordering(self):
        """!
        @brief Returns clustering ordering information about the input data set.
        @details Clustering ordering of data-set contains the information about the internal clustering structure in line with connectivity radius.
        
        @return (ordering_analyser) Analyser of clustering ordering.
        
        @see process()
        @see get_clusters()
        @see get_noise()
        @see get_radius()
        
        """
        
        if (self.__ordering is None):
            self.__ordering = [];
        
            for cluster in self.__clusters:
                for index_object in cluster:
                    optics_object = self.__optics_objects[index_object];
                    if (optics_object.reachability_distance is not None):
                        self.__ordering.append(optics_object.reachability_distance);
            
        return self.__ordering;
    
    
    def get_radius(self):
        """!
        @brief Returns connectivity radius that is calculated and used for clustering by the algorithm.
        @details Connectivity radius may be changed only in case of usage additional parameter of the algorithm - amount of clusters for allocation.
        
        @return (double) Connectivity radius.
        
        @see get_ordering()
        @see get_clusters()
        @see get_noise()
        
        """
        
        return self.__eps;
    

    def get_cluster_encoding(self):
        """!
        @brief Returns clustering result representation type that indicate how clusters are encoded.
        
        @return (type_encoding) Clustering result representation.
        
        @see get_clusters()
        
        """
        
        return type_encoding.CLUSTER_INDEX_LIST_SEPARATION;


    def __expand_cluster_order(self, optics_object):
        """!
        @brief Expand cluster order from not processed optic-object that corresponds to object from input data.
               Traverse procedure is performed until objects are reachable from core-objects in line with connectivity radius.
               Order database is updated during expanding.
               
        @param[in] optics_object (optics_descriptor): Object that hasn't been processed.
        
        """
        
        optics_object.processed = True;
        
        neighbors_descriptor = self.__neighbor_indexes(optics_object);
        optics_object.reachability_distance = None;
        
        self.__ordered_database.append(optics_object);
        
        # Check core distance
        if (len(neighbors_descriptor) >= self.__minpts):
            neighbors_descriptor.sort(key = lambda obj: obj[1]);
            optics_object.core_distance = neighbors_descriptor[self.__minpts - 1][1];
            
            # Continue processing
            order_seed = list();
            self.__update_order_seed(optics_object, neighbors_descriptor, order_seed);
            
            while(len(order_seed) > 0):
                optic_descriptor = order_seed[0];
                order_seed.remove(optic_descriptor);
                
                neighbors_descriptor = self.__neighbor_indexes(optic_descriptor);
                optic_descriptor.processed = True;
                
                self.__ordered_database.append(optic_descriptor);
                
                if (len(neighbors_descriptor) >= self.__minpts):
                    neighbors_descriptor.sort(key = lambda obj: obj[1]);
                    optic_descriptor.core_distance = neighbors_descriptor[self.__minpts - 1][1];
                    
                    self.__update_order_seed(optic_descriptor, neighbors_descriptor, order_seed);
                else:
                    optic_descriptor.core_distance = None;
                    
        else:
            optics_object.core_distance = None;

    
    def __extract_clusters(self):
        """!
        @brief Extract clusters and noise from order database.
        
        """
     
        self.__clusters = [];
        self.__noise = [];

        current_cluster = [];
        for optics_object in self.__ordered_database:
            if ((optics_object.reachability_distance is None) or (optics_object.reachability_distance > self.__eps)):
                if ((optics_object.core_distance is not None) and (optics_object.core_distance <= self.__eps)):
                    if (len(current_cluster) > 0):
                        self.__clusters.append(current_cluster);
                        current_cluster = [];
                        
                    current_cluster.append(optics_object.index_object);
                else:
                    self.__noise.append(optics_object.index_object);
            else:
                current_cluster.append(optics_object.index_object);
        
        if (len(current_cluster) > 0):
            self.__clusters.append(current_cluster);
                

    def __update_order_seed(self, optic_descriptor, neighbors_descriptors, order_seed):
        """!
        @brief Update sorted list of reachable objects (from core-object) that should be processed using neighbors of core-object.
        
        @param[in] optic_descriptor (optics_descriptor): Core-object whose neighbors should be analysed.
        @param[in] neighbors_descriptors (list): List of neighbors of core-object.
        @param[in|out] order_seed (list): List of sorted object in line with reachable distance.
        
        """
        
        for neighbor_descriptor in neighbors_descriptors:
            index_neighbor = neighbor_descriptor[0];
            current_reachable_distance = neighbor_descriptor[1];
            
            if (self.__optics_objects[index_neighbor].processed != True):
                reachable_distance = max(current_reachable_distance, optic_descriptor.core_distance);
                if (self.__optics_objects[index_neighbor].reachability_distance is None):
                    self.__optics_objects[index_neighbor].reachability_distance = reachable_distance;
                    
                    # insert element in queue O(n) - worst case.
                    index_insertion = len(order_seed);
                    for index_seed in range(0, len(order_seed)):
                        if (reachable_distance < order_seed[index_seed].reachability_distance):
                            index_insertion = index_seed;
                            break;
                    
                    order_seed.insert(index_insertion, self.__optics_objects[index_neighbor]);

                else:
                    if (reachable_distance < self.__optics_objects[index_neighbor].reachability_distance):
                        self.__optics_objects[index_neighbor].reachability_distance = reachable_distance;
                        order_seed.sort(key = lambda obj: obj.reachability_distance);


    def __neighbor_indexes(self, optic_object):
        """!
        @brief Return list of indexes of neighbors of specified point for the data.
        
        @param[in] optic_object (optics_descriptor): Object for which neighbors should be returned in line with connectivity radius.
        
        @return (list) List of indexes of neighbors in line the connectivity radius.
        
        """
              
        neighbor_description = [];
        
        for index in range(0, len(self.__sample_pointer), 1):
            if (index == optic_object.index_object):
                continue;
            
            distance = euclidean_distance(self.__sample_pointer[optic_object.index_object], self.__sample_pointer[index]);
            if (distance <= self.__eps):
                neighbor_description.append( [index, distance] );
            
        return neighbor_description;