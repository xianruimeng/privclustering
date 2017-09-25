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

#pragma once


#include <vector>


namespace container {

/**
 *
 * @brief   Collection that stores dynamic of oscillatory network - state of each oscillator on
 *          each iteration.
 *
 */
template <typename DynamicType>
class dynamic_data : public std::vector<DynamicType> {
public:
    std::size_t   m_oscillators = 0;

public:
    dynamic_data(void) = default;

    dynamic_data(const std::size_t p_size) :
            std::vector<DynamicType>(p_size),
            m_oscillators(0)
    { }

    dynamic_data(const std::size_t p_size, const DynamicType & p_value) :
            std::vector<DynamicType>(p_size, p_value),
            m_oscillators(0)
    { }

    dynamic_data(const dynamic_data & p_dynamic) = default;

    dynamic_data(dynamic_data && p_dynamic) = default;

    virtual ~dynamic_data(void) = default;

public:
    void push_back(const DynamicType & p_value) {
        check_set_oscillators(p_value);
        std::vector<DynamicType>::push_back(p_value);
    }

    void push_back(DynamicType && p_value) {
        check_set_oscillators(p_value);
        std::vector<DynamicType>::push_back(p_value);
    }

    void resize(const std::size_t p_size, const std::size_t p_oscillators) {
        std::vector<DynamicType>::resize(p_size);
        m_oscillators = p_oscillators;
    }

    void clear(void) {
        std::vector<DynamicType>::clear();
        m_oscillators = 0;
    }

    std::size_t oscillators(void) const {
        return m_oscillators;
    }

private:
    void check_set_oscillators(const DynamicType & p_value) {
        if (std::vector<DynamicType>::empty()) {
            m_oscillators = p_value.size();
        }
        else if (m_oscillators != p_value.size()) {
            throw std::range_error("Dynamic collection can consist of network states with the same size only");
        }
    }

private:
    using std::vector<DynamicType>::assign;
    using std::vector<DynamicType>::clear;
    using std::vector<DynamicType>::emplace;
    using std::vector<DynamicType>::erase;
    using std::vector<DynamicType>::insert;
    using std::vector<DynamicType>::push_back;
    using std::vector<DynamicType>::pop_back;
    using std::vector<DynamicType>::resize;

    using std::vector<DynamicType>::data;
};

}