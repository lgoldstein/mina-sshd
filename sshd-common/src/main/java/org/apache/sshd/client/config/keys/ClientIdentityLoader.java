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

package org.apache.sshd.client.config.keys;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.util.Objects;

import org.apache.sshd.common.NamedResource;
import org.apache.sshd.common.config.keys.FilePasswordProvider;
import org.apache.sshd.common.session.SessionContext;
import org.apache.sshd.common.util.ValidateUtils;
import org.apache.sshd.common.util.io.IoUtils;
import org.apache.sshd.common.util.io.resource.PathResource;
import org.apache.sshd.common.util.security.SecurityUtils;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public interface ClientIdentityLoader {
    /**
     * <P>A default implementation that assumes a file location that <U>must</U> exist.</P>
     *
     * <P>
     * <B>Note:</B> It calls {@link SecurityUtils#loadKeyPairIdentity(String, InputStream, FilePasswordProvider)}
     * </P>
     */
    ClientIdentityLoader DEFAULT = new ClientIdentityLoader() {
        @Override
        public boolean isValidLocation(NamedResource location) throws IOException {
            Path path = toPath(location);
            return Files.exists(path, IoUtils.EMPTY_LINK_OPTIONS);
        }

        @Override
        public KeyPair loadClientIdentity(
                SessionContext session, NamedResource location, FilePasswordProvider provider)
                    throws IOException, GeneralSecurityException {
            Path path = toPath(location);
            PathResource resource = new PathResource(path);
            try (InputStream inputStream = resource.openInputStream()) {
                return SecurityUtils.loadKeyPairIdentity(session, resource, inputStream, provider);
            }
        }

        @Override
        public String toString() {
            return "DEFAULT";
        }

        private Path toPath(NamedResource location) {
            Objects.requireNonNull(location, "No location provided");

            Path path = Paths.get(ValidateUtils.checkNotNullAndNotEmpty(location.getName(), "No location value for %s", location));
            path = path.toAbsolutePath();
            path = path.normalize();
            return path;
        }
    };

    /**
     * @param location The identity key-pair location - the actual meaning (file, URL, etc.)
     * depends on the implementation.
     * @return {@code true} if it represents a valid location - the actual meaning of
     * the validity depends on the implementation
     * @throws IOException If failed to validate the location
     */
    boolean isValidLocation(NamedResource location) throws IOException;

    /**
     * @param session The {@link SessionContext} for invoking this load command - may
     * be {@code null} if not invoked within a session context (e.g., offline tool).
     * @param location The identity key-pair location - the actual meaning (file, URL, etc.)
     * depends on the implementation.
     * @param provider The {@link FilePasswordProvider} to consult if the location contains
     * an encrypted identity
     * @return The loaded {@link KeyPair} - {@code null} if location is empty
     * and it is OK that it does not exist
     * @throws IOException If failed to access / process the remote location
     * @throws GeneralSecurityException If failed to convert the contents into
     * a valid identity
     */
    KeyPair loadClientIdentity(
        SessionContext session, NamedResource location, FilePasswordProvider provider)
            throws IOException, GeneralSecurityException;
}
