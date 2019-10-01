/*
 * Copyright 2016 LINE Corporation
 *
 * LINE Corporation licenses this file to you under the Apache License,
 * version 2.0 (the "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at:
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations
 * under the License.
 */
package hello;

import java.io.Serializable;

public final class AccessToken implements Serializable {

    public String scope;
    public String access_token;
    public String token_type;
    public Integer expires_in;
    public String refresh_token;
    public String id_token;

    public AccessToken()
    {

    }

    public AccessToken(String scope, String access_token, String token_type, Integer expires_in, String refresh_token, String id_token) {
        this.scope = scope;
        this.access_token = access_token;
        this.token_type = token_type;
        this.expires_in = expires_in;
        this.refresh_token = refresh_token;
        this.id_token = id_token;
    }

}
