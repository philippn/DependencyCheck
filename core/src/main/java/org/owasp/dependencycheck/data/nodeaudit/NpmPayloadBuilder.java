/*
 * This file is part of dependency-check-core.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * Copyright (c) 2017 Steve Springett. All Rights Reserved.
 */
package org.owasp.dependencycheck.data.nodeaudit;

import org.owasp.dependencycheck.analyzer.NodePackageAnalyzer;

import java.util.*;
import javax.json.*;
import javax.annotation.concurrent.ThreadSafe;
import org.apache.commons.collections4.MultiValuedMap;

/**
 * Class used to create the payload to submit to the NPM Audit API service.
 *
 * @author Steve Springett
 * @author Jeremy Long
 */
@ThreadSafe
public final class NpmPayloadBuilder {
    /**
     * Private constructor for utility class.
     */
    private NpmPayloadBuilder() {
        //empty
    }

    /**
     * Builds an npm audit API payload.
     *
     * @param lockJson the package-lock.json
     * @param dependencyMap a collection of module/version pairs that is
     * populated while building the payload
     * @param skipDevDependencies whether devDependencies should be skipped
     * @return the npm audit API payload
     */
    public static JsonObject build(JsonObject lockJson, MultiValuedMap<String, String> dependencyMap,
                                   boolean skipDevDependencies) {
        final int lockJsonVersion = lockJson.containsKey("lockfileVersion") ? lockJson.getInt("lockfileVersion") : 1;
        JsonObject dependencies = lockJson.getJsonObject("dependencies");
        if (lockJsonVersion >= 2 && dependencies == null) {
            dependencies = lockJson.getJsonObject("packages");
        }

        if (dependencies != null) {
            dependencies.forEach((k, value) -> {
                String key = k;
                final int indexOfNodeModule = key.lastIndexOf(NodePackageAnalyzer.NODE_MODULES_DIRNAME + "/");
                if (indexOfNodeModule >= 0) {
                    key = key.substring(indexOfNodeModule + NodePackageAnalyzer.NODE_MODULES_DIRNAME.length() + 1);
                }

                JsonObject dep = (JsonObject) value;
                final String version = dep.getString("version", "");
                final boolean isDev = dep.getBoolean("dev", false);
                if (skipDevDependencies && isDev) {
                    return;
                }
                if (NodePackageAnalyzer.shouldSkipDependency(key, version)) {
                    return;
                }
                dependencyMap.put(key, version);
            });
        }

        final JsonObjectBuilder payloadBuilder = Json.createObjectBuilder();
        for (Map.Entry<String, Collection<String>> entry : dependencyMap.asMap().entrySet()) {
            final JsonArrayBuilder versionsBuilder = Json.createArrayBuilder();
            entry.getValue().forEach(versionsBuilder::add);
            payloadBuilder.add(entry.getKey(), versionsBuilder);
        }
        return payloadBuilder.build();
    }
}
