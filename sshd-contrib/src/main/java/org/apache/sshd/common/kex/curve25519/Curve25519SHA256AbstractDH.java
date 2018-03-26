/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements. See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership. The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.apache.sshd.common.kex.curve25519;

import java.util.Random;

import org.apache.sshd.common.digest.BuiltinDigests;
import org.apache.sshd.common.digest.Digest;
import org.apache.sshd.common.kex.AbstractDH;

/**
 * TODO Add javadoc
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class Curve25519SHA256AbstractDH extends AbstractDH {
    private final byte q_s[] = new byte[Curve25519.KEY_SIZE]; //server's ephemeral public key octet string
    private final byte q_c[] = new byte[Curve25519.KEY_SIZE]; // //client's ephemeral public key octet string
    private final byte privateKeyForKeyAgreement[] = new byte[Curve25519.KEY_SIZE];
    private final byte k_as_byte_array[] = new byte[Curve25519.KEY_SIZE];

    public Curve25519SHA256AbstractDH(Random random) throws Exception {
        //generate public key and private key for key agreement
        random.nextBytes(privateKeyForKeyAgreement);
        Curve25519.keygen(q_s, null, privateKeyForKeyAgreement);
     }

    @Override
    public void setF(byte[] bytes) {
        System.arraycopy(bytes, 0, q_c, 0, bytes.length);
    }

    @Override
    public byte[] getE() throws Exception {
        return q_s;
    }

    @Override
    protected byte[] calculateK() throws Exception {
        // create shared secret
        Curve25519.curve(k_as_byte_array, privateKeyForKeyAgreement, q_c);
        // The whole 32 bytes need to be converted into a big integer following the
        // network byte order
        return stripLeadingZeroes(k_as_byte_array);
    }

    @Override
    public Digest getHash() throws Exception {
        return BuiltinDigests.sha256.create();
    }
}