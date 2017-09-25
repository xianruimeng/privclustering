
#include "../../abycore/util/typedefs.h"
#include <set>
#include <cmath>
#include <vector>
#include <iostream>
#include <iomanip>

#ifndef HCLUSTER_H
#define HCLUSTER_H

using namespace std;

/**
 *
 */

class Cordij {
public:
    int cord_i;
    int cord_j;
    int index;
    //Cordij(); 
    //Cordij(int i, int j, int id) : cord_i(i), cord_j(j), index(id) {}
};

class Cluster {
    uint32_t id; 
    vector<int> ind_set;

public:
    //Cluster();

    void insert_id(int id) {
        ind_set.push_back(id);
    }

    void setPoints(vector<int> &ind) {
        this->ind_set.clear();
        this->ind_set = ind;
    }

    vector<int> getPoints() {
        return ind_set;
    }
};

class HCluster {
public:

    HCluster() {
    };
    ~HCluster();
    HCluster(vector< vector<double> > dist_matrix);

    void AggClustering(uint32_t num_cl);
    void updateDistMatrix(int i, int j);
    int getLevel();
    int getNumberCluters();
    void merge(int i, int j);
    int getMin(std::vector<double> v);
    double lance_william(double d_ij, double d_ik, double d_jk);
    vector< vector<double> >  make_sym_matrix(vector< vector<double> > matrix); //
    void outputCluster();

private:
    int level;
    int num_clutsters;
    int total_points;
    vector< vector<double> > distMatrix;
    vector<Cluster> CLUSTER_Arr;

};

#endif
