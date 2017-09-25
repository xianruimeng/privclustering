/**
*
* Copyright (C) 2014-2017    Andrei Novikov (pyclustering@yandex.ru)
*
* GNU_PUBLIC_LICENSE
*   pyclustering is free software: you can redistribute it and/or modify
*   it under the terms of the GNU General Public License as published by
*   the Free Software Foundation, either version 3 of the License, or
*   (at your option) any later version.
*
*   pyclustering is distributed in the hope that it will be useful,
*   but WITHOUT ANY WARRANTY; without even the implied warranty of
*   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
*   GNU General Public License for more details.
*
*   You should have received a copy of the GNU General Public License
*   along with this program.  If not, see <http://www.gnu.org/licenses/>.
*
*/


#include "gtest/gtest.h"

#include "samples.hpp"

#include "cluster/xmeans.hpp"

#include <algorithm>


using namespace cluster_analysis;


static void
template_length_process_data(const std::shared_ptr<dataset> & data,
                             const dataset & start_centers,
                             const unsigned int kmax,
                             const std::vector<unsigned int> & expected_cluster_length,
                             const splitting_type criterion) {
    cluster_analysis::xmeans solver(start_centers, kmax, 0.0001, criterion);

    cluster_analysis::xmeans_data output_result;
    solver.process(*data.get(), output_result);

    cluster_analysis::cluster_sequence & results = *(output_result.clusters());

    /* Check number of clusters */
    ASSERT_EQ(expected_cluster_length.size(), results.size());

    /* Check cluster sizes */
    std::vector<size_t> obtained_cluster_length;
    for (size_t i = 0; i < results.size(); i++) {
        obtained_cluster_length.push_back(results[i].size());
    }

    std::sort(obtained_cluster_length.begin(), obtained_cluster_length.end());

    std::vector<unsigned int> sorted_expected_cluster_length(expected_cluster_length);
    std::sort(sorted_expected_cluster_length.begin(), sorted_expected_cluster_length.end());

    for (size_t i = 0; i < obtained_cluster_length.size(); i++) {
        ASSERT_EQ(obtained_cluster_length[i], sorted_expected_cluster_length[i]);
    }
}


TEST(utest_xmeans, allocation_bic_sample_simple_01) {
    dataset start_centers = { {3.7, 5.5}, {6.7, 7.5} };
    std::vector<unsigned int> expected_clusters_length = {5, 5};
    template_length_process_data(simple_sample_factory::create_sample(SAMPLE_SIMPLE::SAMPLE_SIMPLE_01), start_centers, 20, expected_clusters_length, splitting_type::BAYESIAN_INFORMATION_CRITERION);
}


TEST(utest_xmeans, allocation_mndl_sample_simple_01) {
    dataset start_centers = { {3.7, 5.5}, {6.7, 7.5} };
    std::vector<unsigned int> expected_clusters_length = {5, 5};
    template_length_process_data(simple_sample_factory::create_sample(SAMPLE_SIMPLE::SAMPLE_SIMPLE_01), start_centers, 20, expected_clusters_length, splitting_type::MINIMUM_NOISELESS_DESCRIPTION_LENGTH);
}


TEST(utest_xmeans, allocation_bic_sample_simple_02) {
    dataset start_centers = { {3.5, 4.8}, {6.9, 7.0}, {7.5, 0.5} };
    std::vector<unsigned int> expected_clusters_length = {10, 5, 8};
    template_length_process_data(simple_sample_factory::create_sample(SAMPLE_SIMPLE::SAMPLE_SIMPLE_02), start_centers, 20, expected_clusters_length, splitting_type::BAYESIAN_INFORMATION_CRITERION);
}


TEST(utest_xmeans, allocation_mndl_sample_simple_02) {
    dataset start_centers = { {3.5, 4.8}, {6.9, 7.0}, {7.5, 0.5} };
    std::vector<unsigned int> expected_clusters_length = {10, 5, 8};
    template_length_process_data(simple_sample_factory::create_sample(SAMPLE_SIMPLE::SAMPLE_SIMPLE_02), start_centers, 20, expected_clusters_length, splitting_type::MINIMUM_NOISELESS_DESCRIPTION_LENGTH);
}


TEST(utest_xmeans, allocation_bic_sample_simple_03) {
    dataset start_centers = { {0.2, 0.1}, {4.0, 1.0}, {2.0, 2.0}, {2.3, 3.9} };
    std::vector<unsigned int> expected_clusters_length = {10, 10, 10, 30};
    template_length_process_data(simple_sample_factory::create_sample(SAMPLE_SIMPLE::SAMPLE_SIMPLE_03), start_centers, 20, expected_clusters_length, splitting_type::BAYESIAN_INFORMATION_CRITERION);
}


TEST(utest_xmeans, allocation_mndl_sample_simple_03) {
    dataset start_centers = { {0.2, 0.1}, {4.0, 1.0}, {2.0, 2.0}, {2.3, 3.9} };
    std::vector<unsigned int> expected_clusters_length = {10, 10, 10, 30};
    template_length_process_data(simple_sample_factory::create_sample(SAMPLE_SIMPLE::SAMPLE_SIMPLE_03), start_centers, 20, expected_clusters_length, splitting_type::MINIMUM_NOISELESS_DESCRIPTION_LENGTH);
}


TEST(utest_xmeans, allocation_bic_sample_simple_04) {
    dataset start_centers = { {1.5, 0.0}, {1.5, 2.0}, {1.5, 4.0}, {1.5, 6.0}, {1.5, 8.0} };
    std::vector<unsigned int> expected_clusters_length = {15, 15, 15, 15, 15};
    template_length_process_data(simple_sample_factory::create_sample(SAMPLE_SIMPLE::SAMPLE_SIMPLE_04), start_centers, 20, expected_clusters_length, splitting_type::BAYESIAN_INFORMATION_CRITERION);
}


TEST(utest_xmeans, allocation_mndl_sample_simple_04) {
    dataset start_centers = { {1.5, 0.0}, {1.5, 2.0}, {1.5, 4.0}, {1.5, 6.0}, {1.5, 8.0} };
    std::vector<unsigned int> expected_clusters_length = {15, 15, 15, 15, 15};
    template_length_process_data(simple_sample_factory::create_sample(SAMPLE_SIMPLE::SAMPLE_SIMPLE_04), start_centers, 20, expected_clusters_length, splitting_type::MINIMUM_NOISELESS_DESCRIPTION_LENGTH);
}
