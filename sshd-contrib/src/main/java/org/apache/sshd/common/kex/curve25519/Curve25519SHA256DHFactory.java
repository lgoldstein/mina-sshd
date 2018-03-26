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

import java.util.Objects;
import java.util.Random;

import org.apache.sshd.common.kex.DHFactory;
import org.apache.sshd.common.util.security.SecurityUtils;

/**
 * TODO Add javadoc
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class Curve25519SHA256DHFactory implements DHFactory {
    protected final Random random;

    // Should be a SecureRandom but we don't insist on it
    public Curve25519SHA256DHFactory(Random random) {
        this.random = Objects.requireNonNull(random, "No random values generator provided");
    }

   @Override
   public boolean isGroupExchange() {
       return false;
   }

   @Override
   public Curve25519SHA256AbstractDH create(Object... os) throws Exception {
       return new Curve25519SHA256AbstractDH(random);
   }

   @Override
   public String getName() {
       return Constants.CURVE25519_SHA256;
   }

   @Override
   public boolean isSupported() {
       return SecurityUtils.isBouncyCastleRegistered();
   }

   public static final class Constants {
       public static final String CURVE25519_SHA256 = "curve25519-sha256@libssh.org";
   }
}
