#include "hcluster.h"

#define DEBUG = 1;



HCluster::HCluster(vector< vector<double> > dist_matrix) {

    //row 
    unsigned rnum = dist_matrix.size();
    distMatrix = dist_matrix;

    //initial number of clusters (points)
    CLUSTER_Arr.resize(rnum);
    total_points = rnum;
    uint32_t k = 0;

    for (unsigned i = 0; i < dist_matrix.size(); ++i) {

        //initialization ...    	
        Cluster c;
        //set cluster id ...
        c.insert_id(i); 
        CLUSTER_Arr[i] = c;
    }
}

HCluster::~HCluster() {
    distMatrix.clear();
    CLUSTER_Arr.clear();

}

void HCluster::AggClustering(uint32_t num_cl) {
 
    int curr_num_clusters = total_points;

    while (curr_num_clusters >= num_cl) {

        // for (int k = 0; k < distMatrix.size(); ++k) {
        //     for (int l = 0; l < distMatrix.size(); ++l) {
        //         cout<<  distMatrix[k][l]<<" ";
        //     } 
        //     cout<<endl;
        // }
        // cout<<"------"<<endl;


        //get minimum index i & j
        //============================//
        //convert to 1-d array ...
        vector<Cordij> cord_vect;
        vector<double> pairwise_dist;

        int indx = 0;
        int new_size = distMatrix.size() * (distMatrix.size() - 1) / 2;
        cord_vect.resize(new_size);
        pairwise_dist.resize(new_size);

        for (unsigned k = 0; k < distMatrix.size(); k++) {
            for (unsigned l = 0; l < k; l++) {
                if (k != l) {

                    Cordij indx_lk;
                    indx_lk.cord_i = k;
                    indx_lk.cord_j = l;
                    indx_lk.index = indx;
                    cord_vect[indx] = indx_lk;

                    pairwise_dist[indx] = distMatrix[k][l];

                    indx++;
                }
            }
        }


        // for (unsigned k = 0; k < pairwise_dist.size(); ++k)
        // {
        //     cout<<"["<<k<<"]:"<<pairwise_dist[k]<<" ";
        // }
        // cout<<endl;

        int min_index = getMin(pairwise_dist);

        int i = cord_vect[min_index].cord_i;
        int j = cord_vect[min_index].cord_j;

        // cout<<"minium index:" << min_index <<endl;
        
    	//merge ith and jth clusters...
        merge(i, j);

        if(CLUSTER_Arr.size() == num_cl) break;

        //update distance metric
        //============================//
        updateDistMatrix(i, j);

        //update clusters();
        //============================//
        curr_num_clusters--;
     
    }
    
    
}

void HCluster::outputCluster(){
    int i;
    for (i = 0;  i < CLUSTER_Arr.size(); i++) {
        vector<int> ids = CLUSTER_Arr[i].getPoints();
        cout<<"Cluster "<< i<<" ( ";
         for(auto p: ids)
             cout<<" "<< p;
        cout<<")"<<endl;
    }

        
}

/***
 * Return the minmum index in the distance array ...
 */
int HCluster::getMin(vector<double> v) {

    int i, min_index = 0;
    double minmum = v[0];

    for (i = 1; i < v.size(); i++) {

        if (v[i] < minmum) {
            minmum = v[i];
            min_index = i;
        }
    }
   
    return min_index;
}

/***
 * Merge the ith and jth cluster in Cluster_ARR
 */
void HCluster::merge(int i, int j) {

    uint32_t k;

    Cluster merge_cluster;
    vector<int> cluster_ij;
    vector<int> c_i_points = CLUSTER_Arr[i].getPoints();
    vector<int> c_j_points = CLUSTER_Arr[j].getPoints();
    
    int c_i_size = c_i_points.size();
    vector<int>::iterator it;
   
    it = cluster_ij.begin();
    cluster_ij.insert(it, c_i_points.begin(), c_i_points.end());    

    it = cluster_ij.begin();
    cluster_ij.insert(it + c_i_size, c_j_points.begin(), c_j_points.end());
       
    merge_cluster.setPoints(cluster_ij);
    vector<Cluster> v;


    for (k = 0; k < CLUSTER_Arr.size(); k++) {
        if (k != i && k != j)
            v.push_back(CLUSTER_Arr[k]);
    }

    v.push_back(merge_cluster);

   // cout<<" temp v size :" <<v.size()<<endl;

    
    CLUSTER_Arr.clear();
    CLUSTER_Arr.resize(v.size());

    for(k =0; k<v.size(); k++){
        CLUSTER_Arr[k] = v[k];
    }
 
    v.clear();
}

/***
 * udpate the distance 
 */
void HCluster::updateDistMatrix(int i, int j) {

    double D_ij = distMatrix[i][j];
    uint32_t k, l;

    uint32_t o_size = distMatrix.size();
    uint32_t new_size = o_size - 1;

    vector< vector<double> > new_distMatrix(new_size);

    for(k = 0 ; k < new_distMatrix.size(); ++k){
        new_distMatrix[k].resize(new_size);
    }
   //new_distMatrix.resize(distMatrix.size() - 1);
    
    int ctr;
    
    //@todo
    vector<double> d_i_vect;
    d_i_vect.resize(distMatrix.size()-2); //@TODO less than 2 ...
    vector<double> d_j_vect;
    d_j_vect.resize(distMatrix.size()-2); //@TODO less than 2 ...

    ctr = 0;
    for (k = 0; k < distMatrix.size(); k++) {
        if(k != i && k!=j){
            d_i_vect[ctr] = distMatrix[k][i];
            d_j_vect[ctr] = distMatrix[k][j];
            ctr++;
        }
    }

    ctr = 0;
    for (k = 0; k < distMatrix.size(); k++) {
        vector<double> row_v;
        if (k != i && k != j) {//

            for (l = 0; l < distMatrix.size(); l++) {
                if (l != i && l != j) {
                    row_v.push_back(distMatrix[k][l]);
                }
            }   
            new_distMatrix[ctr] = row_v;
            ctr++;
        }  
        row_v.clear();
    }
    
    vector<double> dist_temp(new_size - 1);
    
    for(k = 0;  k < new_size-1 ; k++){
        dist_temp[k] =
	       	 lance_william(D_ij, d_i_vect[k], d_j_vect[k]);
    }

    for (k = 0; k < new_size -1 ; k++) {
        new_distMatrix[new_size - 1][k] = dist_temp[k];
        new_distMatrix[k][new_size - 1] = dist_temp[k];
    }

    new_distMatrix[new_size - 1][new_size - 1] = 0.0;

    distMatrix.clear();
    
    distMatrix.resize(new_size);

    for(k = 0; k< new_size; k++){
        distMatrix[k].resize(new_size);
        for(l = 0; l < new_size; l++)
            distMatrix[k][l] = new_distMatrix[k][l];
    }

// #ifdef sssDEBUG
//     for(k = 0; k< new_size; k++){
//         for(l = 0; l < new_size; l++){
//             cout<<distMatrix[k][l]<<" ";
//         }
//         cout<<endl;
//     }

//     cout<<endl;
// #endif

    new_distMatrix.clear();

}

/**
 * single linkage....
 */
double HCluster::lance_william(double d_ij, double d_ik, double d_jk) {

    // cout<<"----"<<endl;
    // cout<<"minimum(d_ik "<<d_ik<<", d_jk"<<d_jk<<"):"<<(d_jk + d_ik - abs(d_ik - d_jk)) / 2.0<<endl;
    // cout<<"----"<<endl;
    
    return (d_jk + d_ik - abs(d_ik - d_jk)) / 2.0;
}

vector< vector<double> >  HCluster::make_sym_matrix(vector< vector<double> > matrix) {
    for (unsigned i = 0; i < matrix.size(); i++) {
        for (unsigned j = 0; j <= i; j++) {
            if (i == j) matrix[i][j] = 0;            
            matrix[j][i] = matrix[i][j];
        }
    }
    return matrix;
}


