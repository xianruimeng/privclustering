"""!

@brief Integration-tests for SOM-SC algorithm.

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

from pyclustering.cluster.tests.somsc_templates import SyncnetTestTemplates;

from pyclustering.samples.definitions import SIMPLE_SAMPLES;


class SomscIntegrationTest(unittest.TestCase):
    def testClusterAllocationSampleSimple1ByCore(self):
        SyncnetTestTemplates.templateLengthProcessData(SIMPLE_SAMPLES.SAMPLE_SIMPLE1, 2, [5, 5], True);

    def testClusterOneAllocationSampleSimple1ByCore(self):
        SyncnetTestTemplates.templateLengthProcessData(SIMPLE_SAMPLES.SAMPLE_SIMPLE1, 1, [10], True);

    def testClusterAllocationSampleSimple2ByCore(self):
        SyncnetTestTemplates.templateLengthProcessData(SIMPLE_SAMPLES.SAMPLE_SIMPLE2, 3, [10, 5, 8], True);

    def testClusterOneAllocationSampleSimple2ByCore(self):
        SyncnetTestTemplates.templateLengthProcessData(SIMPLE_SAMPLES.SAMPLE_SIMPLE2, 1, [23], True);

    def testClusterAllocationSampleSimple3ByCore(self):
        SyncnetTestTemplates.templateLengthProcessData(SIMPLE_SAMPLES.SAMPLE_SIMPLE3, 4, [10, 10, 10, 30], True); 

    def testClusterOneAllocationSampleSimple3ByCore(self):
        SyncnetTestTemplates.templateLengthProcessData(SIMPLE_SAMPLES.SAMPLE_SIMPLE3, 1, [60], True); 

    def testClusterAllocationSampleSimple4ByCore(self):
        SyncnetTestTemplates.templateLengthProcessData(SIMPLE_SAMPLES.SAMPLE_SIMPLE4, 5, [15, 15, 15, 15, 15], True);

    def testClusterOneAllocationSampleSimple4ByCore(self):
        SyncnetTestTemplates.templateLengthProcessData(SIMPLE_SAMPLES.SAMPLE_SIMPLE4, 1, [75], True);

    def testClusterAllocationSampleSimple5ByCore(self):
        SyncnetTestTemplates.templateLengthProcessData(SIMPLE_SAMPLES.SAMPLE_SIMPLE5, 4, [15, 15, 15, 15], True);

    def testClusterOneAllocationSampleSimple5ByCore(self):
        SyncnetTestTemplates.templateLengthProcessData(SIMPLE_SAMPLES.SAMPLE_SIMPLE5, 1, [60], True);

    def testClusterOneDimensionSampleSimple7ByCore(self):
        SyncnetTestTemplates.templateLengthProcessData(SIMPLE_SAMPLES.SAMPLE_SIMPLE7, 2, [10, 10], True);

    def testClusterOneDimensionSampleSimple8ByCore(self):
        SyncnetTestTemplates.templateLengthProcessData(SIMPLE_SAMPLES.SAMPLE_SIMPLE8, 4, None, True);

    def testWrongNumberOfCentersSimpleSample1ByCore(self):
        SyncnetTestTemplates.templateLengthProcessData(SIMPLE_SAMPLES.SAMPLE_SIMPLE1, 3, None, True);

    def testWrongNumberOfCentersSimpleSample2ByCore(self):
        SyncnetTestTemplates.templateLengthProcessData(SIMPLE_SAMPLES.SAMPLE_SIMPLE2, 4, None, True);


    def testClusterAllocationOneDimensionDataByCore(self):
        SyncnetTestTemplates.templateClusterAllocationOneDimensionData(True);


if __name__ == "__main__":
    unittest.main();