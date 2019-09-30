package hello;

/**
 * LINEService用定数クラス
 */
public class LINEConstant {

	/** リクエストヘッダ固定値 */
	public static final String BEARER = "Bearer";

	/** LINEエラーコード */
	public static final String ACCESS_DENIED = "access_denied";

	/** コンテンツタイプ */
	public static final String CONTENT_TYPE_URLENCODED = "application/x-www-form-urlencoded;";

	/**
	 * ヘッダ名
	 */
	public enum HeaderName {
		CONTENT_TYPE("Content-type"),
		AUTHORIZATION("Authorization");

		private final String value;

		private HeaderName(String value) {
			this.value = value;
		}

		public String getValue() {
			return this.value;
		}
	}

	/**
	 * パラメータ名
	 */
	public enum ParameterName {

		RESPONSE_CODE("response_code"),
		GRANT_TYPE("grant_type"),
		CLIENT_ID("client_id"),
		CLIENT_SECRET("client_secret"),
		REDIRECT_URI("redirect_uri"),
		STATE("state"),
		SCOPE("scope"),
		NONCE("nonce"),
		PROMPT("prompt"),
		BOTPROMPT("bot_prompt"),
		CODE("code"),
		ACCESS_TOKEN("access_token"),
		REFRESH_TOKEN("refresh_token");

		private final String value;

		private ParameterName(String value) {
			this.value = value;
		}

		public String getValue() {
			return this.value;
		}
	}

	/**
	 * grant_type
	 */
	public enum GrantType {

		CLIENT_CREDENTIALS("client_credentials"),
		REFRESH_TOKEN("refresh_token"),
		AUTHORIZATION_CODE("authorization_code");

		private final String value;

		private GrantType(String value) {
			this.value = value;
		}

		public String getValue() {
			return this.value;
		}
	}

}
