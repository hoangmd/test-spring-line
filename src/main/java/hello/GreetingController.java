package hello;

import com.sun.deploy.net.HttpResponse;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.client.RestTemplate;
import org.yaml.snakeyaml.introspector.PropertyUtils;



import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URI;
import java.net.URLEncoder;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@Controller
public class GreetingController {

    String channelId = "1627405774";
    String callbackUrl = "https://duc-test-spring.herokuapp.com/auth";
    String channelSecret = "55f97e140a30ff183ecbbf57339133e3";
    String lineAPIURL = "https://api.line.me/oauth2/v2.1/token";

    @GetMapping("/greeting")
    public String greeting(@RequestParam(name="name", required=false, defaultValue="World") String name, Model model) {
        model.addAttribute("name", name);
        return "greeting";
    }

    @GetMapping("/lineauth")
    public String goToAuthPage(){
       // final String state = CommonUtils.getToken();
        final String state = "staterandom";
        final String nonce = "nouncerandom";
        final String url = getLineWebLoginUrl(state, nonce, Arrays.asList("openid", "profile"));
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


        if (error != null || errorCode != null || errorMessage != null){
            return "redirect:/loginCancel";
        }

        /*
        AccessToken token = lineAPIService.accessToken(code);
        if (logger.isDebugEnabled()) {
            logger.debug("scope : " + token.scope);
            logger.debug("access_token : " + token.access_token);
            logger.debug("token_type : " + token.token_type);
            logger.debug("expires_in : " + token.expires_in);
            logger.debug("refresh_token : " + token.refresh_token);
            logger.debug("id_token : " + token.id_token);
        }
        httpSession.setAttribute(ACCESS_TOKEN, token);
        */
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




        /*
        try {
            HttpHeaders headers = new HttpHeaders();
            headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
            MultiValueMap<String, String> map = new LinkedMultiValueMap<>();
            map.add("grant_type", "authorization_code");
            map.add("code", code);
            map.add("redirect_uri", encodedCallbackUrl);
            map.add("client_id", channelId);
            map.add("client_secret", channelSecret);

            RestTemplate restTemplate = new RestTemplate();
            HttpEntity<MultiValueMap<String, String>> request = new HttpEntity<>(map, headers);
            ResponseEntity<AccessToken> token = restTemplate.postForEntity(
                    lineAPIURL, request, AccessToken.class);


            model.addAttribute("access_token", token.getBody().access_token);
            model.addAttribute("id_token", token.getBody().id_token);



        }
        catch(Exception e)
        {
            e.printStackTrace();
        }
    */
        return "success";
    }

    @GetMapping("/got_token")
    public String auth(
            @RequestParam(value = "access_token", required = false) String access_token,
            @RequestParam(value = "id_token", required = false) String id_token, Model model) {

        model.addAttribute("access_token", access_token);
        model.addAttribute("id_token", id_token);
        return "gottoken";
    }

    /*
    public void issueAccessToken(String code) {


        // リクエストヘッダの生成
        Map<String, Object> headers = new HashMap<String, Object>();
        headers.put(LINEConstant.HeaderName.AUTHORIZATION.getValue(), LINEConstant.CONTENT_TYPE_URLENCODED);
        Map<String, String> form = new HashMap<String, String>();
        form.put(LINEConstant.ParameterName.GRANT_TYPE.getValue(), LINEConstant.GrantType.AUTHORIZATION_CODE.getValue());
        form.put(LINEConstant.ParameterName.CLIENT_ID.getValue(), channelId);
        form.put(LINEConstant.ParameterName.CLIENT_SECRET.getValue(), channelSecret);
        form.put(LINEConstant.ParameterName.CODE.getValue(), code);
        form.put(LINEConstant.ParameterName.REDIRECT_URI.getValue(), callbackUrl);

        String url = lineAPIURL;
        HTTPRequestService httpService = new HTTPRequestService();
        String json = httpService.postRequest(url, headers, form);

        logger.info("レスポンス json=[" + json + "]");

        SocialAccessTokenVo accessTokenVo = JsonUtils.convertJsonToObject(json, SocialAccessTokenVo.class);
        dto.setScope(accessTokenVo.getScope());
        dto.setAccessToken(accessTokenVo.getAccessToken());
        dto.setExpiresIn(accessTokenVo.getExpiresIn());
        dto.setRefreshToken(accessTokenVo.getRefreshToken());
        dto.setIdToken(accessTokenVo.getIdToken());
    }

    */

}