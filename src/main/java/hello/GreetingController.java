package hello;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTDecodeException;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.DecodedJWT;
import org.json.JSONObject;
import org.springframework.http.*;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.client.RestTemplate;

import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.util.Arrays;
import java.util.List;

@Controller
public class GreetingController {

    String channelId = "1627405774";
    String callbackUrl = "https://duc-test-spring.herokuapp.com/auth";
    String channelSecret = "55f97e140a30ff183ecbbf57339133e3";
    String lineAPIURL = "https://api.line.me/oauth2/v2.1/token";


    @GetMapping("/lineauth")
    public String goToAuthPage() {
        final String state = "staterandom";
        final String nonce = "nouncerandom";
        final String url = getLineWebLoginUrl(state, nonce, Arrays.asList("openid", "profile", "email"));
        return "redirect:" + url;
    }


    public String getLineWebLoginUrl(String state, String nonce, List<String> scopes) {
        final String encodedCallbackUrl;
        final String scope = String.join("%20", scopes);

        try {
            encodedCallbackUrl = URLEncoder.encode(callbackUrl, "UTF-8");
        } catch (UnsupportedEncodingException e) {
            throw new RuntimeException(e);
        }

        return "https://access.line.me/oauth2/v2.1/authorize?response_type=code"
                + "&client_id=" + channelId
                + "&redirect_uri=" + encodedCallbackUrl
                + "&state=" + state
                + "&scope=" + scope
                + "&nonce=" + nonce;
    }


    @GetMapping("/auth")
    public String auth(
            @RequestParam(value = "code", required = false) String code,
            @RequestParam(value = "state", required = false) String state,
            @RequestParam(value = "scope", required = false) String scope,
            @RequestParam(value = "error", required = false) String error,
            @RequestParam(value = "errorCode", required = false) String errorCode,
            @RequestParam(value = "errorMessage", required = false) String errorMessage, Model model) {


        if (error != null || errorCode != null || errorMessage != null) {
            return "redirect:/loginCancel";
        }

        model.addAttribute("code", code);
        model.addAttribute("state", state);
        model.addAttribute("scope", scope);
        model.addAttribute("error", error);


        final String encodedCallbackUrl;
        try {
            encodedCallbackUrl = URLEncoder.encode(callbackUrl, "UTF-8");
        } catch (UnsupportedEncodingException e) {
            throw new RuntimeException(e);
        }

        // model.addAttribute("callback", callback);


        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
        MultiValueMap<String, String> map = new LinkedMultiValueMap<>();
        map.add("grant_type", "authorization_code");
        map.add("code", code);
        map.add("redirect_uri", callbackUrl);
        map.add("client_id", channelId);
        map.add("client_secret", channelSecret);

        RestTemplate restTemplate = new RestTemplate();
        HttpEntity<MultiValueMap<String, String>> request = new HttpEntity<>(map, headers);
        ResponseEntity<AccessToken> token = restTemplate.postForEntity(
                lineAPIURL, request, AccessToken.class);


        model.addAttribute("access_token", token.getBody().access_token);
        model.addAttribute("id_token", token.getBody().id_token);

        AccessToken accessToken = token.getBody();
        Boolean verifiedSuccessful = verifyIdToken(accessToken.id_token, "nouncerandom");
        model.addAttribute("verifiedSuccessful", verifiedSuccessful.toString());

        IdToken idToken = idToken(accessToken.id_token);
        String email = idToken.email;
        model.addAttribute("email", email);


        //get user profile
        restTemplate = new RestTemplate();
        headers = new HttpHeaders();
        headers.set("Authorization", "Bearer " + accessToken.access_token);
        HttpEntity entity = new HttpEntity(headers);

        ResponseEntity<String> response = restTemplate.exchange(
                "https://api.line.me/v2/profile", HttpMethod.GET, entity, String.class);
        String responseBody = response.getBody();
        model.addAttribute("userProfile", responseBody);

        JSONObject obj = new JSONObject(responseBody);
        String userId = obj.getString("userId");
        String displayName = obj.getString("displayName");
        String pictureUrl = obj.getString("pictureUrl");


        model.addAttribute("userId", userId);
        model.addAttribute("displayName", displayName);
        model.addAttribute("pictureUrl", pictureUrl);


        return "success";
    }


    public IdToken idToken(String id_token) {
        try {
            DecodedJWT jwt = JWT.decode(id_token);
            return new IdToken(
                    jwt.getClaim("iss").asString(),
                    jwt.getClaim("sub").asString(),
                    jwt.getClaim("aud").asString(),
                    jwt.getClaim("ext").asLong(),
                    jwt.getClaim("iat").asLong(),
                    jwt.getClaim("nonce").asString(),
                    jwt.getClaim("name").asString(),
                    jwt.getClaim("email").asString(),
                    jwt.getClaim("picture").asString());
        } catch (JWTDecodeException e) {
            throw new RuntimeException(e);
        }
    }


    public boolean verifyIdToken(String id_token, String nonce) {
        try {
            JWT.require(
                    Algorithm.HMAC256(channelSecret))
                    .withIssuer("https://access.line.me")
                    .withAudience(channelId)
                    .withClaim("nonce", nonce)
                    .acceptLeeway(60) // add 60 seconds leeway to handle clock skew between client and server sides.
                    .build()
                    .verify(id_token);
            return true;
        } catch (JWTVerificationException e) {
            //Invalid signature/claims
            return false;
        }
    }

}