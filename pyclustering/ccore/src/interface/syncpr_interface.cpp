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

#include "interface/sync_interface.h"
#include "interface/syncpr_interface.h"

#include "nnet/syncpr.hpp"


void * syncpr_create(const unsigned int num_osc, const double increase_strength1, const double increase_strength2) {
    return (void *) new syncpr(num_osc, increase_strength1, increase_strength2);
}


void syncpr_destroy(const void * pointer_network) {
    delete (syncpr *) pointer_network;
}


unsigned int syncpr_get_size(const void * pointer_network) {
    return ((syncpr *)pointer_network)->size();
}


void syncpr_train(const void * pointer_network, const void * const patterns) {
    syncpr * network = (syncpr *)pointer_network;

    const pyclustering_package * const package_patterns = (const pyclustering_package * const)patterns;
    std::vector<syncpr_pattern> external_patterns;
    package_patterns->extract(external_patterns);

    network->train(external_patterns);
}


void * syncpr_simulate_static(const void * pointer_network,
                              unsigned int steps,
                              const double time,
                              const void * const pattern,
                              const unsigned int solver,
                              const bool collect_dynamic) 
{
    syncpr * network = (syncpr *)pointer_network;

    const pyclustering_package * const package_pattern = (const pyclustering_package * const)pattern;
    syncpr_pattern external_pattern((int *)package_pattern->data, ((int *)package_pattern->data) + package_pattern->size);

    syncpr_dynamic * dynamic = new syncpr_dynamic();
    network->simulate_static(steps, time, external_pattern, (solve_type)solver, collect_dynamic, (*dynamic));

    return (void *)dynamic;
}


void * syncpr_simulate_dynamic(const void * pointer_network,
                               const void * const pattern,
                               const double order,
                               const unsigned int solver,
                               const bool collect_dynamic,
                               const double step)
{
    syncpr * network = (syncpr *)pointer_network;

    const pyclustering_package * const package_pattern = (const pyclustering_package * const)pattern;
    syncpr_pattern external_pattern((int *)package_pattern->data, ((int *)package_pattern->data) + package_pattern->size);

    syncpr_dynamic * dynamic = new syncpr_dynamic();
    network->simulate_dynamic(external_pattern, order, step, (solve_type)solver, collect_dynamic, (*dynamic));

    return (void *)dynamic;
}


double syncpr_memory_order(const void * pointer_network, const void * const pattern) {
    const pyclustering_package * const package_pattern = (const pyclustering_package * const)pattern;
    syncpr_pattern external_pattern((int *)package_pattern->data, ((int *)package_pattern->data) + package_pattern->size);

    return ((syncpr *)pointer_network)->memory_order(external_pattern);
}


unsigned int syncpr_dynamic_get_size(const void * pointer_network) {
    return ((syncpr_dynamic *)pointer_network)->size();
}

void syncpr_dynamic_destroy(const void * pointer) {
    delete (syncpr_dynamic *)pointer;
}


pyclustering_package * syncpr_dynamic_allocate_sync_ensembles(const void * pointer, const double tolerance) {
    return sync_dynamic_allocate_sync_ensembles(pointer, tolerance, syncpr_dynamic_get_size(pointer) - 1);
}


pyclustering_package * syncpr_dynamic_get_time(const void * pointer) {
    return sync_dynamic_get_time(pointer);
}


pyclustering_package * syncpr_dynamic_get_output(const void * pointer) {
    return sync_dynamic_get_output(pointer);
}