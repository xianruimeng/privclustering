/*
 * timer.hpp
 *
 *  Created on: Sep 16, 2015
 *   Author: xmeng
 */
#ifndef TIMER_HPP_
#define TIMER_HPP_

#include <cstdio>
#include <sys/time.h>

using namespace std;

struct Timer
{
    timeval t1, t2;
    void start()    { gettimeofday(&this->t1, NULL);}
    void stop()     { gettimeofday(&this->t2, NULL);}
    double elapsed_time(){
        double t = (double)(t2.tv_sec-t1.tv_sec)*1.0+(double)(t2.tv_usec-t1.tv_usec)/1000000.0;
        return t;
    }
};

#endif /* TIMER_HPP_ */
