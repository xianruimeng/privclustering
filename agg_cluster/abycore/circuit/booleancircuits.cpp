/**
 \file 		booleancircuits.cpp
 \author	michael.zohner@ec-spride.de
 \copyright	ABY - A Framework for Efficient Mixed-protocol Secure Two-party Computation
			Copyright (C) 2015 Engineering Cryptographic Protocols Group, TU Darmstadt
			This program is free software: you can redistribute it and/or modify
			it under the terms of the GNU Affero General Public License as published
			by the Free Software Foundation, either version 3 of the License, or
			(at your option) any later version.
			This program is distributed in the hope that it will be useful,
			but WITHOUT ANY WARRANTY; without even the implied warranty of
			MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
			GNU Affero General Public License for more details.
			You should have received a copy of the GNU Affero General Public License
			along with this program. If not, see <http://www.gnu.org/licenses/>.
 \brief		A collection of boolean circuits for boolean and yao sharing in the ABY framework
 */

#include "booleancircuits.h"

void BooleanCircuit::Init() {
	m_nShareBitLen = 1;
	m_nNumANDSizes = 1;
	m_vANDs = (non_lin_vec_ctx*) malloc(sizeof(non_lin_vec_ctx) * m_nNumANDSizes);
	m_vANDs[0].bitlen = 1;
	m_vANDs[0].numgates = 0;

	m_nGates = 0;
	if (m_eContext == S_BOOL) {
		m_nRoundsAND = 1;
		m_nRoundsXOR = 0;
		m_nRoundsIN.resize(2, 1);
		m_nRoundsOUT.resize(3, 1);
	} else if (m_eContext == S_YAO) { //|| m_eContext ==  S_YAO_PIPE) { //m_tContext == S_YAO
		m_nRoundsAND = 0;
		m_nRoundsXOR = 0;
		m_nRoundsIN.resize(2);
		m_nRoundsIN[0] = 1;
		m_nRoundsIN[1] = 2;
		m_nRoundsOUT.resize(3, 1);
		m_nRoundsOUT[1] = 0; //the client already holds the output bits from the start
	} else {
		cerr << "Sharing type not implemented for Boolean circuit" << endl;
		exit(0);
	}

	m_nB2YGates = 0;
	m_nA2YGates = 0;
	m_nNumXORVals = 0;
	m_nNumXORGates = 0;
}

void BooleanCircuit::Cleanup() {
	//TODO implement
}

uint32_t BooleanCircuit::PutANDGate(uint32_t inleft, uint32_t inright) {
	uint32_t gateid = m_cCircuit->PutPrimitiveGate(G_NON_LIN, inleft, inright, m_nRoundsAND);

	if (m_eContext == S_BOOL) {
		UpdateInteractiveQueue(gateid);
	} else if (m_eContext == S_YAO) { // || m_eContext == S_YAO_PIPE) {
		//if context == YAO, no communication round is required
		UpdateLocalQueue(gateid);
	} else {
		cerr << "Context not recognized" << endl;
	}

	if (m_pGates[gateid].nvals != INT_MAX) {
		m_vANDs[0].numgates += m_pGates[gateid].nvals;
	}
	return gateid;
}

vector<uint32_t> BooleanCircuit::PutANDGate(vector<uint32_t> inleft, vector<uint32_t> inright) {
	uint32_t lim = min(inleft.size(), inright.size());
	vector<uint32_t> out(lim);
	for (uint32_t i = 0; i < lim; i++)
		out[i] = PutANDGate(inleft[i], inright[i]);
	return out;
}

share* BooleanCircuit::PutANDGate(share* ina, share* inb) {
	return new boolshare(PutANDGate(ina->get_gates(), inb->get_gates()), this);
}

uint32_t BooleanCircuit::PutVectorANDGate(uint32_t choiceinput, uint32_t vectorinput) {
	if (m_eContext != S_BOOL) {
		cerr << "Building a vector AND gate is currently only possible for GMW!" << endl;
		//TODO: prevent error by putting repeater gate on choiceinput and an AND gate between choiceinput and vectorinput
		return 0;
	}


	uint32_t gateid = m_cCircuit->PutNonLinearVectorGate(G_NON_LIN_VEC, choiceinput, vectorinput, m_nRoundsAND);
	UpdateInteractiveQueue(gateid);

	//cout << "Putting a vector and gate between a gate with " << m_pGates[choiceinput].nvals << " and " <<
	//		m_pGates[vectorinput].nvals << ", res gate has nvals = " << m_pGates[gateid].nvals << endl;


	if (m_pGates[gateid].nvals != INT_MAX) {
		//Update vector AND sizes
		//find location of vector AND bitlength
		//int pos = FindBitLenPositionInVec(m_pGates[gateid].nvals, m_vANDs, m_nNumANDSizes);
		int pos = FindBitLenPositionInVec(m_pGates[gateid].gs.avs.bitlen, m_vANDs, m_nNumANDSizes);
		if (pos == -1) {
			//Create new entry for the bit-length
			m_nNumANDSizes++;
			non_lin_vec_ctx* temp = (non_lin_vec_ctx*) malloc(sizeof(non_lin_vec_ctx) * m_nNumANDSizes);
			memcpy(temp, m_vANDs, (m_nNumANDSizes - 1) * sizeof(non_lin_vec_ctx));
			free(m_vANDs);
			m_vANDs = temp;
			//m_vANDs[m_nNumANDSizes - 1].bitlen = m_pGates[gateid].nvals;
			m_vANDs[m_nNumANDSizes - 1].bitlen = m_pGates[gateid].gs.avs.bitlen;
			m_vANDs[m_nNumANDSizes - 1].numgates = m_pGates[choiceinput].nvals; //1
		} else {
			//increase number of vector ANDs for this bitlength by one
			m_vANDs[pos].numgates+=m_pGates[choiceinput].nvals;
		}
	}
	return gateid;
}

share* BooleanCircuit::PutXORGate(share* ina, share* inb) {
	return new boolshare(PutXORGate(ina->get_gates(), inb->get_gates()), this);
}

uint32_t BooleanCircuit::PutXORGate(uint32_t inleft, uint32_t inright) {
	//cout << "inleft = " << inleft << ", inright = " << inright << endl;
	uint32_t gateid = m_cCircuit->PutPrimitiveGate(G_LIN, inleft, inright, m_nRoundsXOR);
	UpdateLocalQueue(gateid);
	m_nNumXORVals += m_pGates[gateid].nvals;
	m_nNumXORGates += 1;
	return gateid;
}

vector<uint32_t> BooleanCircuit::PutXORGate(vector<uint32_t> inleft, vector<uint32_t> inright) {
	uint32_t lim = min(inleft.size(), inright.size());
	vector<uint32_t> out(lim);
	for (uint32_t i = 0; i < lim; i++)
		out[i] = PutXORGate(inleft[i], inright[i]);
	return out;
}

uint32_t BooleanCircuit::PutINGate(uint32_t ninvals, e_role src) {
	uint32_t gateid = m_cCircuit->PutINGate(m_eContext, ninvals, m_nShareBitLen, src, m_nRoundsIN[src]);
	UpdateInteractiveQueue(gateid);
	switch (src) {
	case SERVER:
		m_vInputGates[0].push_back(gateid);
		m_vInputBits[0] += m_pGates[gateid].nvals;
		break;
	case CLIENT:
		m_vInputGates[1].push_back(gateid);
		m_vInputBits[1] += m_pGates[gateid].nvals;
		break;
	case ALL:
		m_vInputGates[0].push_back(gateid);
		m_vInputGates[1].push_back(gateid);
		m_vInputBits[0] += m_pGates[gateid].nvals;
		m_vInputBits[1] += m_pGates[gateid].nvals;
		break;
	default:
		cerr << "Role not recognized" << endl;
		break;
	}

	return gateid;
}

template<class T> uint32_t BooleanCircuit::PutINGate(uint32_t ninvals, T val) {

	uint32_t gateid = PutINGate(ninvals, m_eMyRole);
	//assign value
	GATE* gate = m_pGates + gateid;
	gate->gs.ishare.inval = (UGATE_T*) calloc(ninvals * m_nShareBitLen, sizeof(UGATE_T));

	*gate->gs.ishare.inval = (UGATE_T) val;
	gate->instantiated = true;

	return gateid;
}


template<class T> uint32_t BooleanCircuit::PutINGate(uint32_t ninvals, T* val, e_role role) {
	uint32_t gateid = PutINGate(ninvals, role);
	if (role == m_eMyRole) {
		//assign value
		GATE* gate = m_pGates + gateid;
		gate->gs.ishare.inval = (UGATE_T*) calloc(ceil_divide(ninvals * m_nShareBitLen, GATE_T_BITS), sizeof(UGATE_T));
		memcpy(gate->gs.ishare.inval, val, ceil_divide(ninvals * m_nShareBitLen, 8));

		gate->instantiated = true;
	}
	return gateid;
}

uint32_t BooleanCircuit::PutINGate(uint32_t nvals, uint64_t val, e_role role) {
	//return PutINGate(nvals, &val, role);
	uint32_t gateid = PutINGate(nvals, role);
	if (role == m_eMyRole) {
		//assign value
		GATE* gate = m_pGates + gateid;
		gate->gs.ishare.inval = (UGATE_T*) calloc(ceil_divide(nvals * m_nShareBitLen, sizeof(UGATE_T) * 8), sizeof(UGATE_T));
		memcpy(gate->gs.ishare.inval, &val, ceil_divide(nvals * m_nShareBitLen, 8));

		gate->instantiated = true;
	}

	return gateid;
}

template<class T> share* BooleanCircuit::InternalPutINGate(uint32_t nvals, T val, uint32_t bitlen, e_role role) {
	share* shr = new boolshare(bitlen, this);
	assert(nvals <= sizeof(T) * 8);
	T mask;
	if(nvals & 0x03 == 0) {
		mask = (((T) 1)<<nvals) - 1;
	} else {
		memset(&mask, 0xFF, ceil_divide(nvals, 8));
	}

	for (uint32_t i = 0; i < bitlen; i++) {
		shr->set_gate(i, PutINGate(nvals, (val >> i) & mask, role));
	}
	return shr;
}



template<class T> share* BooleanCircuit::InternalPutINGate(uint32_t nvals, T* val, uint32_t bitlen, e_role role) {
	share* shr = new boolshare(bitlen, this);
	uint32_t typebitlen = sizeof(T) * 8;
	uint32_t typebyteiters = ceil_divide(bitlen, typebitlen);
	uint64_t tmpval_bytes = typebyteiters * nvals;// * sizeof(T);
	//uint32_t valstartpos = ceil_divide(nvals, typebitlen);
	T* tmpval = (T*) malloc(tmpval_bytes);

	for (uint32_t i = 0; i < bitlen; i++) {
		memset(tmpval, 0, tmpval_bytes);
		for (uint32_t j = 0; j < nvals; j++) {
			//tmpval[j / typebitlen] += ((val[j] >> (i % typebitlen) & 0x01) << j);
			tmpval[j /typebitlen] += (((val[j * typebyteiters + i/typebitlen] >> (i % typebitlen)) & 0x01) << (j%typebitlen));
		}
		shr->set_gate(i, PutINGate(nvals, tmpval, role));
	}
	free(tmpval);
	return shr;
}


uint32_t BooleanCircuit::PutOUTGate(uint32_t parentid, e_role dst) {
	uint32_t gateid = m_cCircuit->PutOUTGate(parentid, dst, m_nRoundsOUT[dst]);

	UpdateInteractiveQueue(gateid);

	switch (dst) {
	case SERVER:
		m_vOutputGates[0].push_back(gateid);
		m_vOutputBits[0] += m_pGates[gateid].nvals;
		break;
	case CLIENT:
		m_vOutputGates[1].push_back(gateid);
		m_vOutputBits[1] += m_pGates[gateid].nvals;
		break;
	case ALL:
		m_vOutputGates[0].push_back(gateid);
		m_vOutputGates[1].push_back(gateid);
		m_vOutputBits[0] += m_pGates[gateid].nvals;
		m_vOutputBits[1] += m_pGates[gateid].nvals;
		break;
	default:
		cerr << "Role not recognized" << endl;
		break;
	}

	return gateid;
}

share* BooleanCircuit::PutOUTGate(share* parent, e_role dst) {
	return new boolshare(PutOUTGate(parent->get_gates(), dst), this);
}

vector<uint32_t> BooleanCircuit::PutOUTGate(vector<uint32_t> parentids, e_role dst) {
	vector<uint32_t> gateid = m_cCircuit->PutOUTGate(parentids, dst, m_nRoundsOUT[dst]);

	//TODO: optimize
	for (uint32_t i = 0; i < gateid.size(); i++) {
		UpdateInteractiveQueue(gateid[i]);
		switch (dst) {
		case SERVER:
			m_vOutputGates[0].push_back(gateid[i]);
			m_vOutputBits[0] += m_pGates[gateid[i]].nvals;
			break;
		case CLIENT:
			m_vOutputGates[1].push_back(gateid[i]);
			m_vOutputBits[1] += m_pGates[gateid[i]].nvals;
			break;
		case ALL:
			m_vOutputGates[0].push_back(gateid[i]);
			m_vOutputGates[1].push_back(gateid[i]);
			m_vOutputBits[0] += m_pGates[gateid[i]].nvals;
			m_vOutputBits[1] += m_pGates[gateid[i]].nvals;
			break;
		default:
			cerr << "Role not recognized" << endl;
			break;
		}
	}

	return gateid;
}



//share* BooleanCircuit::PutCONSGate(UGATE_T val, uint32_t nvals) {
//	return new boolshare(PutConstantGate(val, nvals), this);
//}

share* BooleanCircuit::PutCONSGate(uint32_t nvals, UGATE_T val, uint32_t bitlen) {
	share* shr = new boolshare(bitlen, this);
	UGATE_T tmpval;
	for (uint32_t i = 0; i < bitlen; i++) {
		(val>>i) & 0x01 ? tmpval = ~0: tmpval = 0;
		tmpval = tmpval % (1<<nvals);
		shr->set_gate(i, PutConstantGate(tmpval, nvals));
	}
	return shr;
}

share* BooleanCircuit::PutCONSGate(uint32_t nvals, uint8_t* val, uint32_t bitlen) {
	share* shr = new boolshare(bitlen, this);
	uint32_t bytelen = ceil_divide(bitlen, 8);
	uint32_t valbytelen = ceil_divide(nvals, 8);
	uint8_t* tmpval = (uint8_t*) malloc(valbytelen);

	for (uint32_t i = 0; i < bitlen; i++) {
		shr->set_gate(i, PutConstantGate(val[i] & 0x01, nvals));
	}
	free(tmpval);
	return shr;
}

share* BooleanCircuit::PutCONSGate(uint32_t nvals, uint32_t* val, uint32_t bitlen) {
	share* shr = new boolshare(bitlen, this);
	for (uint32_t i = 0; i < bitlen; i++) {
		shr->set_gate(i, PutConstantGate((val[i >> 5] >> i) & 0x01, nvals));
	}
	return shr;
}



uint32_t BooleanCircuit::PutConstantGate(UGATE_T val, uint32_t nvals) {
	uint32_t gateid = m_cCircuit->PutConstantGate(m_eContext, val, nvals, m_nShareBitLen);
	UpdateLocalQueue(gateid);
	return gateid;
}

uint32_t BooleanCircuit::PutINVGate(uint32_t parentid) {
	uint32_t gateid = m_cCircuit->PutINVGate(parentid);
	UpdateLocalQueue(gateid);
	return gateid;
}

vector<uint32_t> BooleanCircuit::PutINVGate(vector<uint32_t> parentid) {
	vector<uint32_t> out(parentid.size());
	for (uint32_t i = 0; i < out.size(); i++)
		out[i] = PutINVGate(parentid[i]);
	return out;
}

share* BooleanCircuit::PutINVGate(share* parent) {
	return new boolshare(PutINVGate(parent->get_gates()), this);
}

uint32_t BooleanCircuit::PutY2BCONVGate(uint32_t parentid) {
	vector<uint32_t> in(1, parentid);
	uint32_t gateid = m_cCircuit->PutCONVGate(in, 1, S_BOOL, m_nShareBitLen);
	//TODO increasing the depth shouldn't be necessary but somehow leads to errors in make runtest
	m_pGates[gateid].depth++;
	//UpdateLocalQueue(gateid);
	UpdateLocalQueue(gateid);
	//a Y input gate cannot be parent to a Y2B gate. Alternatively, put a Boolean input gate
	assert(m_pGates[parentid].type != G_IN);

	return gateid;
}

uint32_t BooleanCircuit::PutB2YCONVGate(uint32_t parentid) {
	vector<uint32_t> in(1, parentid);
	uint32_t gateid = m_cCircuit->PutCONVGate(in, 2, S_YAO, m_nShareBitLen);
	UpdateInteractiveQueue(gateid);

	//treat similar to input gate of client and server
	m_nB2YGates += m_pGates[gateid].nvals;

	return gateid;
}

vector<uint32_t> BooleanCircuit::PutY2BCONVGate(vector<uint32_t> parentid) {
	vector<uint32_t> out(parentid.size());
	for (uint32_t i = 0; i < parentid.size(); i++) {
		out[i] = PutY2BCONVGate(parentid[i]);
	}
	return out;
}

vector<uint32_t> BooleanCircuit::PutB2YCONVGate(vector<uint32_t> parentid) {
	vector<uint32_t> out(parentid.size());
	for (uint32_t i = 0; i < parentid.size(); i++) {
		out[i] = PutB2YCONVGate(parentid[i]);
	}

	return out;
}

share* BooleanCircuit::PutY2BGate(share* ina) {
	return new boolshare(PutY2BCONVGate(ina->get_gates()), this);
}

share* BooleanCircuit::PutB2YGate(share* ina) {
	return new boolshare(PutB2YCONVGate(ina->get_gates()), this);
}

vector<uint32_t> BooleanCircuit::PutA2YCONVGate(vector<uint32_t> parentid) {
	vector<uint32_t> srvshares(m_pGates[parentid[0]].sharebitlen);
	vector<uint32_t> clishares(m_pGates[parentid[0]].sharebitlen);

	for (uint32_t i = 0; i < m_pGates[parentid[0]].sharebitlen; i++) {
		srvshares[i] = m_cCircuit->PutCONVGate(parentid, 1, S_YAO, m_nShareBitLen);
		m_pGates[srvshares[i]].gs.pos = 2 * i;
		m_pGates[srvshares[i]].depth++; //increase depth by 1 since yao is evaluated before arith
		UpdateInteractiveQueue(srvshares[i]);

		clishares[i] = m_cCircuit->PutCONVGate(parentid, 2, S_YAO, m_nShareBitLen);
		m_pGates[clishares[i]].gs.pos = 2 * i + 1;
		m_pGates[clishares[i]].depth++; //increase depth by 1 since yao is evaluated before arith
		UpdateInteractiveQueue(clishares[i]);
	}

	m_nA2YGates += m_pGates[parentid[0]].nvals * m_pGates[parentid[0]].sharebitlen;


	return PutAddGate(srvshares, clishares);
}

share* BooleanCircuit::PutA2YGate(share* ina) {
	return new boolshare(PutA2YCONVGate(ina->get_gates()), this);
}

//TODO: implement other SIMD gate types! Also put this into its own class
uint32_t BooleanCircuit::PutCombinerGate(vector<uint32_t> input) {
	uint32_t gateid = m_cCircuit->PutCombinerGate(input);

	UpdateLocalQueue(gateid);
	return gateid;
}

uint32_t BooleanCircuit::PutCombineAtPosGate(vector<uint32_t> input, uint32_t pos) {
	uint32_t gateid = m_cCircuit->PutCombineAtPosGate(input, pos);
	UpdateLocalQueue(gateid);
	return gateid;
}

uint32_t BooleanCircuit::PutSubsetGate(uint32_t input, uint32_t* posids, uint32_t nvals) {
	uint32_t gateid = m_cCircuit->PutSubsetGate(input, posids, nvals);
	UpdateLocalQueue(gateid);
	return gateid;
}

/**
 * create new vector gate, built from input vector gate with len nvals
 * place old values from indices at posids to result
 * \param	input	gate ids
 * \param	posids	LUT
 * \param	nvals	the length of the vector
 */
share* BooleanCircuit::PutSubsetGate(share* input, uint32_t* posids, uint32_t nvals) {
	share* out = new boolshare(input->size(), this);
	for(uint32_t i = 0; i < input->size(); i++) {
		out->set_gate(i, PutSubsetGate(input->get_gate(i), posids, nvals));
	}
	return out;
}

uint32_t BooleanCircuit::PutStructurizedCombinerGate(vector<uint32_t> input, uint32_t pos_start,
		uint32_t pos_incr, uint32_t nvals) {
	uint32_t gateid = m_cCircuit->PutStructurizedCombinerGate(input, pos_start, pos_incr, nvals);
	UpdateLocalQueue(gateid);
	return gateid;
}

share* BooleanCircuit::PutStructurizedCombinerGate(share* input, uint32_t pos_start,
		uint32_t pos_incr, uint32_t nvals) {
	share* out= new boolshare(1, this);
	out->set_gate(0, PutStructurizedCombinerGate(input->get_gates(), pos_start, pos_incr, nvals));
	return out;
}

vector<uint32_t> BooleanCircuit::PutSplitterGate(uint32_t input) {
	vector<uint32_t> gateid = m_cCircuit->PutSplitterGate(input);
	for (uint32_t i = 0; i < gateid.size(); i++)
		UpdateLocalQueue(gateid[i]);
	return gateid;
}

share* BooleanCircuit::PutSplitterGate(share* input) {
	assert(input->size() == 1); //TODO works for gates of size 1 only currently
	return new boolshare(PutSplitterGate(input->get_gate(0)), this);
}

uint32_t BooleanCircuit::PutRepeaterGate(uint32_t input, uint32_t nvals) {
	uint32_t gateid = m_cCircuit->PutRepeaterGate(input, nvals);
	UpdateLocalQueue(gateid);
	return gateid;
}

share* BooleanCircuit::PutRepeaterGate(share* input, uint32_t nvals) {
	share* share = new boolshare(input->size(), this);
	for(uint32_t i = 0; i < input->size(); i++)
		share->set_gate(i, PutRepeaterGate(input->get_gate(i), nvals));
	return share;
}

share* BooleanCircuit::PutPermutationGate(share* input, uint32_t* positions) {
	share* out = new boolshare(1, this);
	out->set_gate(0, PutPermutationGate(input->get_gates(), positions));
	return out;
}

uint32_t BooleanCircuit::PutPermutationGate(vector<uint32_t> input, uint32_t* positions) {
	uint32_t gateid = m_cCircuit->PutPermutationGate(input, positions);
	UpdateLocalQueue(gateid);
	return gateid;
}

uint32_t BooleanCircuit::PutCallbackGate(vector<uint32_t> in, uint32_t rounds, void (*callback)(GATE*, void*),
		void* infos, uint32_t nvals) {

	uint32_t gateid = m_cCircuit->PutCallbackGate(in, rounds, callback, infos, nvals);

	if(rounds > 0) {
		UpdateInteractiveQueue(gateid);
	} else {
		UpdateLocalQueue(gateid);
	}
	return gateid;
}

share* BooleanCircuit::PutCallbackGate(share* in, uint32_t rounds, void (*callback)(GATE*, void*),
		void* infos, uint32_t nvals) {
	return new boolshare(PutCallbackGate(in->get_gates(), rounds, callback, infos, nvals), this);
}

//enqueue interactive gate queue
void BooleanCircuit::UpdateInteractiveQueue(uint32_t gateid) {
	if (m_pGates[gateid].depth + 1 > m_vInteractiveQueueOnLvl.size()) {
		m_vInteractiveQueueOnLvl.resize(m_pGates[gateid].depth + 1);
		if (m_pGates[gateid].depth + 1 > m_nMaxDepth) {
			m_nMaxDepth = m_pGates[gateid].depth + 1;
		}
	}
	m_vInteractiveQueueOnLvl[m_pGates[gateid].depth].push_back(gateid);
	m_nGates++;
}

//enqueue locally evaluated gate queue
void BooleanCircuit::UpdateLocalQueue(uint32_t gateid) {
	if (m_pGates[gateid].depth + 1 > m_vLocalQueueOnLvl.size()) {
		//cout << "increasing size of local queue" << endl;
		m_vLocalQueueOnLvl.resize(m_pGates[gateid].depth + 1);
		if (m_pGates[gateid].depth + 1 > m_nMaxDepth) {
			m_nMaxDepth = m_pGates[gateid].depth + 1;
		}
	}
	m_vLocalQueueOnLvl[m_pGates[gateid].depth].push_back(gateid);

	m_nGates++;
}

//shift val by pos positions to the left and fill with zeros
//TODO eliminate multiple constant gates
vector<uint32_t> BooleanCircuit::LShift(vector<uint32_t> val, uint32_t pos, uint32_t nvals) {
	vector<uint32_t> out(val.size());
	uint32_t i, zerogate = PutConstantGate(0, nvals);
	for (i = 0; i < pos && i < val.size(); i++) {
		out[i] = zerogate;
	}
	for (i = pos; i < val.size(); i++) {
		out[i] = val[i - pos];
	}
	return out;
}

share* BooleanCircuit::PutADDGate(share* ina, share* inb) {
	//TODO carry computation not verified
	bool carry = max(ina->size(), inb->size()) < max(ina->max_size(), inb->max_size());
	assert(ina->size() == inb->size());
	//cout << "Carry? " << (carry? " true " : " false ") << ina->size() << ", " << inb->size() << ", " <<
	//		ina->max_size() << ", " << inb->max_size() << endl;
	return new boolshare(PutAddGate(ina->get_gates(), inb->get_gates(), carry), this);
}


vector<uint32_t> BooleanCircuit::PutAddGate(vector<uint32_t> left, vector<uint32_t> right, BOOL bCarry) {
	if (m_eContext == S_BOOL) {
		return PutDepthOptimizedAddGate(left, right, bCarry);
	} else {
		return PutSizeOptimizedAddGate(left, right, bCarry);
	}
}

vector<uint32_t> BooleanCircuit::PutMulGate(vector<uint32_t> a, vector<uint32_t> b, uint32_t resbitlen) {
	if(a.size() != b.size()) {
		uint32_t zerogate = PutConstantGate(0, m_pGates[a[0]].nvals);
		if(a.size() > b.size())
			b.resize(a.size(), zerogate);
		else
			a.resize(b.size(), zerogate);
	}
	//cout << "a.size() = " << a.size() << ", b.size() = " << b.size() << endl;
	uint32_t rep = a.size();
	vector<vector<uint32_t> > vAdds(rep);
	uint32_t zerogate = PutConstantGate(0, m_pGates[a[0]].nvals);

	// Compute AND between all bits
#ifdef ZDEBUG
	cout << "Starting to construct multiplication gate for " << rep << " bits" << endl;
#endif
	uint32_t lim = min(resbitlen, 2 * rep);

	for (uint32_t i = 0, ctr; i < rep; i++) {
		ctr = 0;
		vAdds[i].resize(lim);
#ifdef ZDEBUG
		cout << "New Iteration with ctr = " << ctr << ", and lim = " << lim << endl;
#endif
		for (uint32_t j = 0; j < i && ctr < lim; j++, ctr++) {
			vAdds[i][ctr] = zerogate;
		}
		for (uint32_t j = 0; j < rep && ctr < lim; j++, ctr++) {
			vAdds[i][ctr] = PutANDGate(a[j], b[i]);
		}
		for (uint32_t j = i; j < rep && ctr < lim; j++, ctr++) {
			vAdds[i][ctr] = zerogate;
		}
	}

	return PutWideAddGate(vAdds, lim);
}

share* BooleanCircuit::PutMULGate(share* ina, share* inb) {
	return new boolshare(PutMulGate(ina->get_gates(), inb->get_gates(), min(ina->size() + inb->size(), max(ina->max_size(), inb->max_size()))), this);
}

share* BooleanCircuit::PutGEGate(share* ina, share* inb) {
	share* shr = new boolshare(1, this);
	shr->set_gate(0, PutGEGate(ina->get_gates(), inb->get_gates()));
	return shr;
}
share* BooleanCircuit::PutEQGate(share* ina, share* inb) {
	share* shr = new boolshare(1, this);
	shr->set_gate(0, PutEQGate(ina->get_gates(), inb->get_gates()));
	return shr;
}
share* BooleanCircuit::PutMUXGate(share* ina, share* inb, share* sel) {
	return new boolshare(PutMUXGate(ina->get_gates(), inb->get_gates(), sel->get_gate(0)), this);
}

vector<uint32_t> BooleanCircuit::PutWideAddGate(vector<vector<uint32_t> > ins, uint32_t resbitlen) {
	// build a balanced binary tree
	vector<vector<uint32_t> >& survivors = ins;

	while (survivors.size() > 1) {
		unsigned j = 0;
		for (unsigned i = 0; i < survivors.size();) {
			if (i + 1 >= survivors.size()) {
				survivors[j++] = survivors[i++];
			} else {
				survivors[j++] = PutSizeOptimizedAddGate(survivors[i], survivors[i + 1], false);
				i += 2;
			}
		}
		survivors.resize(j);
	}

	return survivors[0];
}

vector<uint32_t> BooleanCircuit::PutSUBGate(vector<uint32_t> a, vector<uint32_t> b) {
	//pad with leading zeros
	if(a.size() != b.size()) {
		uint32_t zerogate = PutConstantGate(0, m_pGates[a[0]].nvals);
		if(a.size() > b.size()) {
			b.resize(a.size(), zerogate);
		} else {
			a.resize(b.size(), zerogate);
		}
	}

	//assert(a.size() == b.size());
	uint32_t bitlen = a.size();
	vector<uint32_t> C(bitlen);
	uint32_t i, bc, bxc, ainvNbxc, ainvNbxcObc, axb;
	vector<uint32_t> ainv(bitlen);
	vector<uint32_t> out(bitlen);

	for (i = 0; i < bitlen; i++) {
		ainv[i] = PutINVGate(a[i]);
	}

	C[0] = PutConstantGate(0, m_pGates[a[0]].nvals);

	for (i = 0; i < bitlen - 1; i++) {
		//===================
		// New Gates
		// b[i] and c[i]
		bc = PutANDGate(b[i], C[i]);

		// b[i] xor c[i]
		bxc = PutXORGate(b[i], C[i]);

		ainvNbxc = PutANDGate(ainv[i], bxc);

		// C[i+1] -> (inv(a)AND(b XOR C[i])) OR (b AND C[i])
		C[i + 1] = PutORGate(ainvNbxc, bc);
	}

	for (i = 0; i < bitlen; i++) {
		// a[i] xor b[i]
		axb = PutXORGate(a[i], b[i]);
		out[i] = PutXORGate(axb, C[i]);
	}

	return out;
}

share* BooleanCircuit::PutSUBGate(share* ina, share* inb) {

	return new boolshare(PutSUBGate(ina->get_gates(), inb->get_gates()), this);
}

vector<uint32_t> BooleanCircuit::PutSizeOptimizedAddGate(vector<uint32_t> a, vector<uint32_t> b, BOOL bCarry) {
	// left + right mod (2^Rep)
	// Construct C[i] gates
	uint32_t rep = a.size();// + (!!bCarry);
	vector<uint32_t> C(rep);
	uint32_t axc, bxc, acNbc;

	C[0] = PutConstantGate(0, m_pGates[a[0]].nvals); //the second parameter stands for the number of vals

	uint32_t i = 0;
	for (; i < rep - 1; i++) {
		//===================
		// New Gates
		// a[i] xor c[i]
		axc = PutXORGate(a[i], C[i]);

		// b[i] xor c[i]
		bxc = PutXORGate(b[i], C[i]);

		// axc AND bxc
		acNbc = PutANDGate(axc, bxc);

		// C[i+1]
		C[i + 1] = PutXORGate(C[i], acNbc);
	}

#ifdef ZDEBUG
	cout << "Finished carry generation" << endl;
#endif

	if (bCarry) {
		axc = PutXORGate(a[i], C[i]);

		// b[i] xor c[i]
		bxc = PutXORGate(b[i], C[i]);

		// axc AND bxc
		acNbc = PutANDGate(axc, bxc);
	}

#ifdef ZDEBUG
	cout << "Finished additional carry generation" << endl;
#endif

	// Construct a[i] xor b[i] gates
	vector<uint32_t> AxB(rep);
	for (uint32_t i = 0; i < rep; i++) {
		// a[i] xor b[i]
		AxB[i] = PutXORGate(a[i], b[i]);
	}

#ifdef ZDEBUG
	cout << "Finished parity on inputs" << endl;
#endif

	// Construct Output gates of Addition
	vector<uint32_t> out(rep + (!!bCarry));
	for (uint32_t i = 0; i < rep; i++) {
		out[i] = PutXORGate(C[i], AxB[i]);
	}

#ifdef ZDEBUG
	cout << "Finished parity on inputs xor carries" << endl;
#endif

	if (bCarry)
		out[rep] = PutXORGate(C[i], acNbc);

#ifdef ZDEBUG
	cout << "Finished parity on additional carry and inputs" << endl;
#endif

	return out;
}

//computes: ci = a > b ? 1 : 0; but assumes both values to be of equal length!
uint32_t BooleanCircuit::PutGEGate(vector<uint32_t> a, vector<uint32_t> b) {
	if (m_eContext == S_BOOL) {
		return PutDepthOptimizedGEGate(a, b);
	} else {
		return PutSizeOptimizedGEGate(a, b);

	}
}

//computes: ci = a > b ? 1 : 0; but assumes both values to be of equal length!
uint32_t BooleanCircuit::PutSizeOptimizedGEGate(vector<uint32_t> a, vector<uint32_t> b) {
	uint32_t ci = 0, ci1, ac, bc, acNbc;
	ci = PutConstantGate((UGATE_T) 0, m_pGates[a[0]].nvals);
	for (uint32_t i = 0; i < a.size(); i++, ci = ci1) {
		ac = PutXORGate(a[i], ci);
		bc = PutXORGate(b[i], ci);
		acNbc = PutANDGate(ac, bc);
		ci1 = PutXORGate(a[i], acNbc);
	}

	return ci;
}

uint32_t BooleanCircuit::PutEQGate(vector<uint32_t> a, vector<uint32_t> b) {
	uint32_t rep = a.size(), temp;
	vector<uint32_t> xors(rep);
	for (uint32_t i = 0; i < rep; i++) {
		temp = PutXORGate(a[i], b[i]);
		xors[i] = PutINVGate(temp);
	}

	// AND of all xor's
	return PutWideGate(G_NON_LIN, xors);
}

uint32_t BooleanCircuit::PutORGate(uint32_t a, uint32_t b) {
	return PutINVGate(PutANDGate(PutINVGate(a), PutINVGate(b)));
}

vector<uint32_t> BooleanCircuit::PutORGate(vector<uint32_t> a, vector<uint32_t> b) {
	uint32_t reps = min(a.size(), b.size());
	vector<uint32_t> out(reps);
	for (uint32_t i = 0; i < reps; i++) {
		out[i] = PutORGate(a[i], b[i]);
	}
	return out;
}

share* BooleanCircuit::PutORGate(share* a, share* b) {
	return new boolshare(PutORGate(a->get_gates(), b->get_gates()), this);
}

/* if c [0] = s & a[0], c[1] = s & a[1], ...*/
share* BooleanCircuit::PutANDVecGate(share* ina, share* inb) {
	uint32_t rep = ina->size();
	share* out = new boolshare(rep, this);

	if (m_eContext == S_BOOL) {
		for (uint32_t i = 0; i < rep; i++) {
			out->set_gate(i, PutVectorANDGate(inb->get_gate(i), ina->get_gate(i)));
		}
	} else {
		//cout << "Putting usual AND gate" << endl;
		for (uint32_t i = 0; i < rep; i++) {
			uint32_t bvec = PutRepeaterGate(inb->get_gate(i), m_pGates[ina->get_gate(i)].nvals);
			out->set_gate(i, PutANDGate(ina->get_gate(i), bvec));
		}
	}
	return out;
}

/* if s == 0 ? b : a*/
vector<uint32_t> BooleanCircuit::PutMUXGate(vector<uint32_t> a, vector<uint32_t> b, uint32_t s, BOOL vecand) {

	vector<uint32_t> out;
	uint32_t rep = a.size();
	uint32_t sab, ab;

	out.resize(rep);

	uint32_t nvals=1;
	for(uint32_t i = 0; i < a.size(); i++) {
		if(m_pGates[a[i]].nvals > nvals)
			nvals = m_pGates[a[i]].nvals;
	}
	for(uint32_t i = 0; i < b.size(); i++)
		if(m_pGates[b[i]].nvals > nvals)
			nvals = m_pGates[a[i]].nvals;

	if (m_eContext == S_BOOL && vecand && nvals == 1) {
		//TODO implement multiplexer gate using a permutation gate (wire values need a transformation)
		//vector<uint32_t> sel_gate = PutSplitterGate(s);
		//uint32_t avec = Put
		uint32_t avec = PutCombinerGate(a);
		uint32_t bvec = PutCombinerGate(b);

		out = PutSplitterGate(PutVecANDMUXGate(avec, bvec, s));

	} else {
		for (uint32_t i = 0; i < rep; i++) {
			ab = PutXORGate(a[i], b[i]);
			sab = PutANDGate(s, ab);
			out[i] = PutXORGate(b[i], sab);
		}
	}

	return out;
}

share* BooleanCircuit::PutVecANDMUXGate(share* a, share* b, share* s) {
	return new boolshare(PutVecANDMUXGate(a->get_gates(), b->get_gates(), s->get_gates()), this);
}

/* if s == 0 ? b : a*/
vector<uint32_t> BooleanCircuit::PutVecANDMUXGate(vector<uint32_t> a, vector<uint32_t> b, vector<uint32_t> s) {
	uint32_t nmuxes = a.size();

	vector<uint32_t> out(nmuxes);
	uint32_t sab, ab;

	//cout << "Putting Vector AND gate" << endl;

	for (uint32_t i = 0; i < nmuxes; i++) {
		ab = PutXORGate(a[i], b[i]);
		sab = PutVectorANDGate(s[i], ab);
		out[i] = PutXORGate(b[i], sab);
	}

	return out;
}

/* if s == 0 ? b : a*/
uint32_t BooleanCircuit::PutVecANDMUXGate(uint32_t a, uint32_t b, uint32_t s) {
	uint32_t ab, sab;
	ab = PutXORGate(a, b);
	if (m_eContext == S_BOOL) {
		sab = PutVectorANDGate(s, ab);
	} else {
		uint32_t svec = PutRepeaterGate(s, m_pGates[ab].nvals);
		sab = PutANDGate(svec, ab);
	}
	return PutXORGate(b, sab);
}

uint32_t BooleanCircuit::PutWideGate(e_gatetype type, vector<uint32_t> ins) {
	// build a balanced binary tree
	vector<uint32_t>& survivors = ins;

	while (survivors.size() > 1) {
		unsigned j = 0;
		for (unsigned i = 0; i < survivors.size();) {
			if (i + 1 >= survivors.size()) {
				survivors[j++] = survivors[i++];
			} else {
				if (type == G_NON_LIN)
					survivors[j++] = PutANDGate(survivors[i], survivors[i + 1]);
				else
					survivors[j++] = PutXORGate(survivors[i], survivors[i + 1]);

				i += 2;
			}
		}
		survivors.resize(j);
	}
	return survivors[0];
}

//if s == 0: a stays a, else a becomes b
vector<vector<uint32_t> > BooleanCircuit::PutCondSwapGate(vector<uint32_t> a, vector<uint32_t> b, uint32_t s, BOOL vectorized) {
	uint32_t rep = min(a.size(), b.size());

	vector<vector<uint32_t> > out(2);
	out[0].resize(rep);
	out[1].resize(rep);

	//cout << "b.nvals = " << m_pGates[b[0]].nvals << ", b.size = " << b.size() <<  endl;

	uint32_t ab, snab, svec;

	if (m_eContext == S_YAO) {

		if (m_pGates[s].nvals < m_pGates[a[0]].nvals)
			svec = PutRepeaterGate(s, m_pGates[a[0]].nvals);
		else
			svec = s;
		//cout << "b.nvals = " << m_pGates[b[0]].nvals << ", b.size = " << b.size() <<  endl;

		for (uint32_t i = 0; i < rep; i++) {
			ab = PutXORGate(a[i], b[i]);
			//snab = PutVectorANDGate(ab, s);

			snab = PutANDGate(svec, ab);

			//swap here to change swap-behavior of condswap
			out[0][i] = PutXORGate(snab, a[i]);
			out[1][i] = PutXORGate(snab, b[i]);
		}
	} else {
		if (vectorized) {
			out[0].resize(1);
			out[1].resize(1);

			ab = PutXORGate(a[0], b[0]);
			snab = PutVectorANDGate(s, ab);
			//uint32_t svec = PutRepeaterGate(s, 32);
			//snab = PutANDGate(svec, ab);
			out[0][0] = PutXORGate(snab, a[0]);
			out[1][0] = PutXORGate(snab, b[0]);
		} else {
			//Put combiner and splitter gates
			uint32_t avec = PutCombinerGate(a);
			uint32_t bvec = PutCombinerGate(b);

			ab = PutXORGate(avec, bvec);
			snab = PutVectorANDGate(s, ab);
			out[0] = PutSplitterGate(PutXORGate(snab, avec));
			out[1] = PutSplitterGate(PutXORGate(snab, bvec));
		}
	}

	/*uint32_t avec = m_cCircuit->PutCombinerGate(a);
	 uint32_t bvec = m_cCircuit->PutCombinerGate(b);

	 uint32_t abvec = PutXORGate(avec, bvec);
	 uint32_t snabvec = PutVectorANDGate(s, abvec);

	 out[0] = m_cCircuit->PutSplitterGate(PutXORGate(snabvec, avec));
	 out[1] = m_cCircuit->PutSplitterGate(PutXORGate(snabvec, bvec));*/

	/*for(uint32_t i=0; i<rep; i++)
	 {
	 ab = PutXORGate(a[i], b[i]);
	 //snab = PutVectorANDGate(ab, s);
	 snab = PutANDGate(s, ab);

	 //swap here to change swap-behavior of condswap
	 out[0][i] = PutXORGate(snab, a[i]);
	 out[1][i] = PutXORGate(snab, b[i]);
	 }*/
	return out;
}

//Returns val if b==1 and 0 else
//TODO implement vector MTs
vector<uint32_t> BooleanCircuit::PutELM0Gate(vector<uint32_t> val, uint32_t b) {
	vector<uint32_t> out(val.size());
	for (uint32_t i = 0; i < val.size(); i++) {
		out[i] = PutANDGate(val[i], b);
	}
	return out;
}



/**
* ==========================================================================
* ==========================================================================
*/


// a = values, b = indexes of each value, n = size of a and b
share* BooleanCircuit::PutArgMinGate(share** a, share** b, uint32_t nvals) {
	
	vector<vector<uint32_t> > min(nvals);
	uint32_t i;
	for (i = 0; i < nvals; i++) {
		min[i] = a[i]->get_gates();
	}

	vector<vector<uint32_t> > min_idx(nvals);

	for (i = 0; i < nvals; i++) {
		min_idx[i] = b[i]->get_gates();
	}

	return new boolshare(PutArgMinGate(min, min_idx), this);
}


// a = values, b = indexes of each value, n = size of a and b
vector<uint32_t> BooleanCircuit::PutArgMinGate(vector<vector<uint32_t> > a, 
											 vector<vector<uint32_t> > min_idx){

	// build a balanced binary tree
	uint32_t cmp;
	uint32_t avec, bvec;
	
	vector<vector<uint32_t> > m_vELMs = a;
	vector<vector<uint32_t> > temp_indx = min_idx;


	while (m_vELMs.size() > 1) {
		unsigned j = 0;
		for (unsigned i = 0; i < m_vELMs.size();) {
			if (i + 1 >= m_vELMs.size()) {
				m_vELMs[j] = m_vELMs[i];
				temp_indx[j] = temp_indx[i];
				i++;
				j++;
			} else {
				//	cmp = bc->PutGTTree(m_vELMs[i], m_vELMs[i+1]);
				if (m_eContext == S_YAO) {
					cmp = PutSizeOptimizedGEGate(m_vELMs[i], m_vELMs[i + 1]);
					m_vELMs[j] = PutMUXGate(m_vELMs[i + 1], m_vELMs[i], cmp);
					temp_indx[j] = PutMUXGate(temp_indx[i + 1], temp_indx[i], cmp);

				} else {
					cmp = PutDepthOptimizedGEGate(m_vELMs[i], m_vELMs[i + 1]);
					m_vELMs[j] = PutMUXGate(m_vELMs[i + 1], m_vELMs[i], cmp);
					temp_indx[j] = PutMUXGate(temp_indx[i + 1], temp_indx[i], cmp);

					//TODO: something is off here
					//avec = PutCombinerGate(m_vELMs[i]);
					//bvec = PutCombinerGate(m_vELMs[j]);
					//m_vELMs[j] = PutSplitterGate(PutVectorANDGate(cmp, PutXORGate(avec, bvec)));
				}

				i += 2;
				j++;
			}
		}
		m_vELMs.resize(j);
		temp_indx.resize(j);

	}
	return temp_indx[0];
}
//*/


/**
* ==========================================================================
* ==========================================================================
*
*/

// a = values, b = indexes of each value, n = size of a and b
share* BooleanCircuit::PutMinGate(share** a, uint32_t nvals) {
	vector<vector<uint32_t> > min(nvals);
	uint32_t i;
	for (i = 0; i < nvals; i++) {
		min[i] = a[i]->get_gates();
	}
	return new boolshare(PutMinGate(min), this);
}


// a = values, b = indexes of each value, n = size of a and b
vector<uint32_t> BooleanCircuit::PutMinGate(vector<vector<uint32_t> > a) {
	// build a balanced binary tree
	uint32_t cmp;
	uint32_t avec, bvec;
	vector<vector<uint32_t> > m_vELMs = a;

	while (m_vELMs.size() > 1) {
		unsigned j = 0;
		for (unsigned i = 0; i < m_vELMs.size();) {
			if (i + 1 >= m_vELMs.size()) {
				m_vELMs[j] = m_vELMs[i];
				i++;
				j++;
			} else {
				//	cmp = bc->PutGTTree(m_vELMs[i], m_vELMs[i+1]);
				if (m_eContext == S_YAO) {
					cmp = PutSizeOptimizedGEGate(m_vELMs[i], m_vELMs[i + 1]);
					m_vELMs[j] = PutMUXGate(m_vELMs[i + 1], m_vELMs[i], cmp);
				} else {
					cmp = PutDepthOptimizedGEGate(m_vELMs[i], m_vELMs[i + 1]);
					m_vELMs[j] = PutMUXGate(m_vELMs[i + 1], m_vELMs[i], cmp);
					//TODO: something is off here
					//avec = PutCombinerGate(m_vELMs[i]);
					//bvec = PutCombinerGate(m_vELMs[j]);
					//m_vELMs[j] = PutSplitterGate(PutVectorANDGate(cmp, PutXORGate(avec, bvec)));
				}

				i += 2;
				j++;
			}
		}
		m_vELMs.resize(j);
	}
	return m_vELMs[0];
}



// a = values, b = indicies of each value, n = size of a and b
void BooleanCircuit::PutMinIdxGate(share** a, share** b, uint32_t nvals, share** minval_shr, share** minid_shr) {
	vector<vector<uint32_t> > val(nvals);
	vector<vector<uint32_t> > ids(nvals);

	vector<uint32_t> minval(1);
	vector<uint32_t> minid(1);

	for (uint32_t i = 0; i < nvals; i++) {
		val[i] = a[i]->get_gates();
		ids[i] = b[i]->get_gates();
	}

	PutMinIdxGate(val, ids, minval, minid);

	*minval_shr = new boolshare(minval, this);
	*minid_shr = new boolshare(minid, this);
}


// a = values, idx = indices of each value, n = size of a and b
void BooleanCircuit::PutMinIdxGate(vector<vector<uint32_t> > a, vector<vector<uint32_t> > idx,
		vector<uint32_t>& minval, vector<uint32_t>& minid) {
	// build a balanced binary tree
	uint32_t cmp;
	uint32_t avec, bvec;
	vector<vector<uint32_t> > m_vELMs = a;

#ifdef USE_MULTI_MUX_GATES
	uint32_t nvariables = 2;
	share **vala, **valb, **valout, *tmpval, *tmpidx, *cond;
	if(m_eContext == S_BOOL) {
		vala = (share**) malloc(sizeof(share*) * nvariables);
		valb = (share**) malloc(sizeof(share*) * nvariables);
		valout = (share**) malloc(sizeof(share*) * nvariables);
		tmpval = new boolshare(a[0].size(), this);
		tmpidx = new boolshare(idx[0].size(), this);
		cond = new boolshare(1, this);
	}
#endif

	while (m_vELMs.size() > 1) {
		unsigned j = 0;
		for (unsigned i = 0; i < m_vELMs.size();) {
			if (i + 1 >= m_vELMs.size()) {
				m_vELMs[j] = m_vELMs[i];
				i++;
				j++;
			} else {
				//	cmp = bc->PutGTTree(m_vELMs[i], m_vELMs[i+1]);
				if (m_eContext == S_BOOL) {
					cmp = PutDepthOptimizedGEGate(m_vELMs[i], m_vELMs[i + 1]);
#ifdef USE_MULTI_MUX_GATES
					//Multimux
					cond->set_gate(0, cmp);
					vala[0] = new boolshare(m_vELMs[i+1], this);
					vala[1] = new boolshare(idx[i+1], this);

					valb[0] = new boolshare(m_vELMs[i], this);
					valb[1] = new boolshare(idx[i], this);

					valout[0] = tmpval;
					valout[1] = tmpidx;

					PutMultiMUXGate(vala, valb, cond, nvariables, valout);
					m_vELMs[j] = tmpval->get_gates();
					idx[j] = tmpidx->get_gates();
#else
					m_vELMs[j] = PutMUXGate(m_vELMs[i + 1], m_vELMs[i], cmp);
					idx[j] = PutMUXGate(idx[i + 1], idx[i], cmp);
#endif
				} else {
					cmp = PutSizeOptimizedGEGate(m_vELMs[i], m_vELMs[i + 1]);
					m_vELMs[j] = PutMUXGate(m_vELMs[i + 1], m_vELMs[i], cmp);
					idx[j] = PutMUXGate(idx[i + 1], idx[i], cmp);

				}

				i += 2;
				j++;
			}
		}
		m_vELMs.resize(j);
		idx.resize(j);
	}
	minval = m_vELMs[0];
	minid = idx[0];

#ifdef USE_MULTI_MUX_GATES
	if(m_eContext == S_BOOL) {
		free(vala);
		free(valb);
		free(valout);
		delete tmpval;
		delete tmpidx;
		delete cond;
	}
#endif
}

uint32_t BooleanCircuit::PutDepthOptimizedGEGate(vector<uint32_t> a, vector<uint32_t> b) {
	uint32_t i, size, ctr_head = 0, ctr_tail = 0, rem = 0;
	uint32_t rep = min(a.size(), b.size());
	vector<uint32_t> agtb(rep);
	vector<uint32_t> eq(2 * rep);

	//Put the leaf comparison nodes from which the tree is built
	for (i = 0; i < rep; i++) {
		agtb[i] = PutANDGate(a[i], PutINVGate(b[i])); //PutBitGreaterThanGate(a[i], b[i]);
	}

	//cout << "Starting bit or" << endl;
	for (; ctr_head < rep - 1; ctr_head++) {
		eq[ctr_head] = PutINVGate(PutXORGate(a[ctr_head + 1], b[ctr_head + 1]));
	}

	size = rep;
	while (size > 1) {
		rem = size % 2;
		size = floor(size / 2);

		for (i = 0; i < size; i++, ctr_tail += 2) {
			agtb[i] = PutXORGate(agtb[2 * i + 1], PutANDGate(eq[ctr_tail], agtb[2 * i])); //PutANDGate(agtb[2*i], equals...]))
		}
		ctr_tail--;
		if (size > 1) {
			for (i = 0; i < size - 1; i++, ctr_head++) {
				eq[ctr_head] = PutANDGate(eq[ctr_head - (size * 2 - 2 - i) - rem], eq[ctr_head - (size * 2 - 3 - i) - rem]);
			}
		}
		if (rem) {
			agtb[size] = agtb[size * 2];
			eq[ctr_head] = eq[ctr_head - size];
			ctr_head++;
			size++;
		}
	}
#ifdef ZDEBUG
	cout << "Finished greater than tree with adress: " << agtb[0] << ", and size: " << size << endl;
#endif
	return agtb[0];
}

//TODO: there is a bug when adding 3 and 1 as two 2-bit numbers and expecting a carry
vector<uint32_t> BooleanCircuit::PutDepthOptimizedAddGate(vector<uint32_t> a, vector<uint32_t> b, BOOL bCARRY) {
	uint32_t id, rep = min(a.size(), b.size());
	vector<uint32_t> out(a.size() + bCARRY);
	vector<uint32_t> parity(a.size()), carry(rep), parity_zero(rep);

	for (uint32_t i = 0; i < rep; i++) { //0-th layer
		parity[i] = PutXORGate(a[i], b[i]);
		parity_zero[i] = parity[i];
		carry[i] = PutANDGate(a[i], b[i]);
	}

	for (uint32_t i = 1; i <= (uint32_t) ceil(log(rep) / log(2)); i++) {
		for (uint32_t j = 0; j < rep; j++) {
			if (j % (uint32_t) pow(2, i) >= pow(2, (i - 1))) {
				id = pow(2, (i - 1)) + pow(2, i) * ((uint32_t) floor(j / (pow(2, i)))) - 1;
				carry[j] = PutINVGate(PutANDGate(PutINVGate(PutANDGate(parity[j], carry[id])), PutINVGate(carry[j]))); // c = (p and c-1) or c = (((p and c-1) xor 1) and (c xor 1)) xor 1)
				parity[j] = PutANDGate(parity[j], parity[id]);
			}
		}
	}

	out[0] = parity_zero[0];
	for (uint32_t i = 1; i < rep; i++) {
		out[i] = PutXORGate(parity_zero[i], carry[i - 1]);
	}
	if (bCARRY)	//Do I expect a carry in the most significant bit position?
		out[rep + 1] = carry[rep - 1];

	return out;
}

uint32_t BooleanCircuit::PutIdxGate(uint32_t r, uint32_t maxidx) {
	if (r > maxidx) {
		r = maxidx;
		cout << "Warning: Index bigger than maxidx for IndexGate" << endl;
	}
	uint32_t digit, limit = ceil_log2(maxidx);
	vector<uint32_t> temp(limit);	// = m_nFrontier;
#ifdef ZDEBUG
			cout << "index for r = " << r << endl;
#endif
	for (uint32_t j = 0; j < limit; j++) {
		digit = (r >> j) & 1;

		temp[j] = PutConstantGate((UGATE_T) digit, 1);
		//cout << "gate: " << out[j] << ": " << digit << endl;
	}

	return PutCombinerGate(temp);
}

void BooleanCircuit::PutMultiMUXGate(share** Sa, share** Sb, share* sel, uint32_t nshares, share** Sout) {

	vector<uint32_t> inputsa, inputsb;
	uint32_t *posids;
	uint32_t bitlen = 0;
	uint32_t nvals = m_pGates[sel->get_gate(0)].nvals;

	//Yao not allowed, if so just put standard muxes. TODO
	assert(m_eContext == S_BOOL);

	for(uint32_t i = 0; i < nshares; i++) {
		bitlen += Sa[i]->size();
	}

	uint32_t total_nvals = bitlen * nvals;
	share* vala = new boolshare(bitlen, this);
	share* valb = new boolshare(bitlen, this);

	//cout << "setting gate" << endl;
	for(uint32_t i = 0, idx; i < bitlen; i++) {
		for(uint32_t j = 0, ctr = 0; j < nshares && (i >= ctr || j == 0); j++) {
			if(i < (ctr+Sa[j]->size())) {
				idx = i - ctr;
				//cout << "for i = " << i << " taking j = " << j << " and ctr = " << ctr << endl;
				vala->set_gate(i, Sa[j]->get_gate(idx));
				valb->set_gate(i, Sb[j]->get_gate(idx));
			}
			ctr+=Sa[j]->size();
		}
	}

	share* avec = PutStructurizedCombinerGate(vala, 0, 1, total_nvals);
	share* bvec = PutStructurizedCombinerGate(valb, 0, 1, total_nvals);

	share* out = PutVecANDMUXGate(avec, bvec, sel);

	//cout << "Setting out gates "  << endl;
	for(uint32_t i = 0, idx; i < bitlen; i++) {
		for(uint32_t j = 0, ctr = 0; j < nshares && (i >= ctr || j == 0); j++) {
			if(i < (ctr+Sa[j]->size())) {
				idx = i - ctr;
				Sout[j]->set_gate(idx, PutStructurizedCombinerGate(out, i, bitlen, nvals)->get_gate(0));
			}
			ctr+=Sa[j]->size();
		}

	}

}

void BooleanCircuit::Reset() {
	Circuit::Reset();

	free(m_vANDs);
	m_nNumANDSizes = 1;
	m_vANDs = (non_lin_vec_ctx*) malloc(sizeof(non_lin_vec_ctx) * m_nNumANDSizes);
	m_vANDs[0].bitlen = 1;
	m_vANDs[0].numgates = 0;
	m_nB2YGates = 0;
	m_nA2YGates = 0;
	m_nNumXORVals = 0;
	m_nNumXORGates = 0;
}

