/*
 * Copyright (C) 2010 Felix Bechstein
 * 
 * This file is part of WebSMS.
 * 
 * This program is free software; you can redistribute it and/or modify it under
 * the terms of the GNU General Public License as published by the Free Software
 * Foundation; either version 3 of the License, or (at your option) any later
 * version.
 * 
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE. See the GNU General Public License for more
 * details.
 * 
 * You should have received a copy of the GNU General Public License along with
 * this program; If not, see <http://www.gnu.org/licenses/>.
 */
package org.herrlado.websms.connector.magtifunge;

import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.apache.http.HttpResponse;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.client.utils.URLEncodedUtils;
import org.apache.http.entity.StringEntity;
import org.apache.http.message.BasicHeader;
import org.apache.http.protocol.HTTP;

import de.ub0r.android.lib.apis.TelephonyWrapper;
import de.ub0r.android.websms.connector.common.Connector;
import de.ub0r.android.websms.connector.common.ConnectorSpec;
import de.ub0r.android.websms.connector.common.ConnectorSpec.SubConnectorSpec;
import de.ub0r.android.websms.connector.common.Utils;
import de.ub0r.android.websms.connector.common.WebSMSException;

import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.preference.PreferenceManager;
import android.util.Log;

/**
 * Receives commands coming as broadcast from WebSMS.
 * 
 * @author flx
 */
public class ConnectorMagtifun extends Connector {
	/** Tag for debug output. */
	private static final String TAG = "WebSMS.magtifun.ge";

	/** Login URL, to send Login (POST). */
	private static final String LOGIN_URL = "http://www.magtifun.ge/index.php?page=11&lang=ge";
	
	private static final String BALANCE_URL = "http://www.magtifun.ge/index.php?page=2&lang=ge";

	/** Send SMS URL(POST) / Free SMS Count URL(GET). */
	private static final String SMS_URL = "http://www.magtifun.ge/scripts/sms_send.php";

	/** Encoding to use. */
	private static final String ENCODING = "UTF-8";

	/** HTTP Header User-Agent. */
	private static final String FAKE_USER_AGENT = "Mozilla/5.0 (Windows; U;"
			+ " Windows NT 5.1; de; rv:1.9.0.9) Gecko/2009040821"
			+ " Firefox/3.0.9 (.NET CLR 3.5.30729)";

	/** This String will be matched if the user is logged in. */
	private static final String MATCH_LOGIN_SUCCESS = "მოგესალმებით";

	/**
	 * Pattern to extract free sms count from sms page. Looks like.
	 */
	public static final Pattern BALANCE_MATCH_PATTERN = Pattern
			.compile(
					"თქვენ ანგარიშზეა .*?english.*?>(\\d{1,})<.*?კრედიტი.*?და .*?english.*?>(\\d{1,})<.*?ლარი",
					Pattern.DOTALL);

	// private static final String SEND_CHECK_STATUS_PATTERN =
	// "შეტყობინება გაგზავნილია ნომერზე";

	private static final String PAGE_ENCODING = "UTF-8";

	private static final String PARAM_recipients = "recipients";

	private static final String PARAM_message_body = "message_body";

	private static final String PARAM_act = "act";

	private static final String PARAM_act_VALUE = "1";

	private static final String PARAM_user = "user";

	private static final String PARAM_password = "password";

	private static final int MAX_LENGTH = 3 * 146;

	private static final int MAX_LENGTH_UCS2 = 3 * 57;

	/**
	 * {@inheritDoc}
	 */
	@Override
	public final ConnectorSpec initSpec(final Context context) {
		final String name = context.getString(R.string.con_name);
		final ConnectorSpec c = new ConnectorSpec(name);
		c.setAuthor(// .
		context.getString(R.string.con_author));
		c.setBalance(null);
		// c.(context.getString(R.string.preferences));

		c.setCapabilities(ConnectorSpec.CAPABILITIES_UPDATE
				| ConnectorSpec.CAPABILITIES_SEND
				| ConnectorSpec.CAPABILITIES_PREFS);
		c.addSubConnector(c.getName(),c.getName(), SubConnectorSpec.FEATURE_MULTIRECIPIENTS);
		return c;
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public final ConnectorSpec updateSpec(final Context context,
			final ConnectorSpec connectorSpec) {
		final SharedPreferences p = PreferenceManager
				.getDefaultSharedPreferences(context);
		if (p.getBoolean(Preferences.ENABLED, false)) {
			if (p.getString(Preferences.PASSWORD, "").length() > 0) {
				connectorSpec.setReady();
			} else {
				connectorSpec.setStatus(ConnectorSpec.STATUS_ENABLED);
			}
		} else {
			connectorSpec.setStatus(ConnectorSpec.STATUS_INACTIVE);
		}
		return connectorSpec;
	}

	/**
	 * b This post data is needed for log in.
	 * 
	 * @param username
	 *            username
	 * @param password
	 *            password
	 * @return array of params
	 * @throws UnsupportedEncodingException
	 *             if the url can not be encoded
	 */
	private static String getLoginPost(final String username,
			final String password) throws UnsupportedEncodingException {
		final StringBuilder sb = new StringBuilder();
		sb.append(PARAM_user).append("=");
		sb.append(URLEncoder.encode(username, ENCODING));
		sb.append("&");
		sb.append(PARAM_password).append("=");
		sb.append(URLEncoder.encode(password, ENCODING));
		sb.append("&");
		sb.append(PARAM_act).append("=").append(PARAM_act_VALUE);
		return sb.toString();
	}

	/**
	 * These post data is needed for sending a sms.
	 * 
	 * @param ctx
	 *            {@link ConnectorContext}
	 * @return array of params
	 * @throws Exception
	 *             if an error occures.
	 */
	private String getSmsPost(final ConnectorContext ctx) throws Exception {

		final String[] tos = ctx.getCommand().getRecipients();
			
		
		StringBuffer  recipient = new StringBuffer();
			String sep = "";
			for(String to : tos){
				recipient.append(sep).append(Utils.getRecipientsNumber(to).trim());
				sep = ",";
			}

		String text = ctx.getCommand().getText();

		int[] result = TelephonyWrapper.getInstance().calculateLength(text,
				false);

		boolean ucs2 = result[3] > 1;
		if (ucs2) {
			if (text.length() > MAX_LENGTH_UCS2) {
				throw new WebSMSException(ctx.context,
						R.string.error_long_for_ucs2);
			}
		} else if (text.length() > MAX_LENGTH) {
			throw new WebSMSException(ctx.context, R.string.error_long_for_gsm);
		}

		final StringBuilder sb = new StringBuilder();
		sb.append(PARAM_recipients).append("=")
				.append(URLEncoder.encode(recipient.toString(), PAGE_ENCODING));
		sb.append("&");
		sb.append(PARAM_message_body).append("=")
				.append(URLEncoder.encode(text, PAGE_ENCODING));
		return sb.toString();
	}

	/**
	 * Login to arcor.
	 * 
	 * @param ctx
	 *            {@link ConnectorContext}
	 * @return true if successfullu logged in, false otherwise.
	 * @throws WebSMSException
	 *             if any Exception occures.
	 */
	private boolean login(final ConnectorContext ctx) throws WebSMSException {
		try {
			final SharedPreferences p = ctx.getPreferences();
			final HttpPost request = createPOST(
					LOGIN_URL,
					getLoginPost(p.getString(Preferences.USERNAME, ""),
							p.getString(Preferences.PASSWORD, "")));
			final HttpResponse response = ctx.getClient().execute(request);
			final String cutContent = Utils.stream2str(response.getEntity()
					.getContent());
			if (cutContent.indexOf(MATCH_LOGIN_SUCCESS) == -1) {
				throw new WebSMSException(ctx.getContext(), R.string.error_pw);
			}

			notifyFreeCount(ctx, cutContent);

		} catch (final Exception e) {
			throw new WebSMSException(e.getMessage());
		}
		return true;
	}

	/**
	 * Create and Prepare a Post Request. Set also an User-Agent
	 * 
	 * @param url
	 *            http post url
	 * @param urlencodedparams
	 *            key=value pairs as url encoded string
	 * @return HttpPost
	 * @throws Exception
	 *             if an error occures
	 */
	private static HttpPost createPOST(final String url,
			final String urlencodedparams) throws Exception {
		final HttpPost post = new HttpPost(url);
		post.setHeader("User-Agent", FAKE_USER_AGENT);
		post.setHeader(new BasicHeader(HTTP.CONTENT_TYPE,
				URLEncodedUtils.CONTENT_TYPE));
		post.setEntity(new StringEntity(urlencodedparams));
		return post;
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	protected final void doUpdate(final Context context, final Intent intent)
			throws WebSMSException {
		// Log.i(TAG, "update");
		final ConnectorContext ctx = ConnectorContext.create(context, intent);
		this.login(ctx);
		// this.updateBalance(ctx);
		// }
	}

	/**
	 * Updates balance andl pushes it to WebSMS.
	 * 
	 * @param ctx
	 *            {@link ConnectorContext}
	 * @throws WebSMSException
	 *             on an error
	 */
//	private void updateBalance(final ConnectorContext ctx)
//			throws WebSMSException {
//		try {
//			final HttpResponse response = ctx.getClient().execute(
//					new HttpGet(SMS_URL));
//			this.notifyFreeCount(ctx,
//					Utils.stream2str(response.getEntity().getContent()));
//
//		} catch (final Exception ex) {
//			throw new WebSMSException(ex.getMessage());
//		}
//	}

	/**
	 * Sends an sms via HTTP POST.
	 * 
	 * @param ctx
	 *            {@link ConnectorContext}
	 * @return successfull?
	 * @throws WebSMSException
	 *             on an error
	 */
	private boolean sendSms(final ConnectorContext ctx) throws WebSMSException {
		try {
			final HttpResponse response = ctx.getClient().execute(
					createPOST(SMS_URL, this.getSmsPost(ctx)));
			return this.afterSmsSent(ctx, response);
		} catch (final Exception ex) {
			throw new WebSMSException(ex.getMessage());
		}
	}

	/**
	 * Handles content after sms sending.
	 * 
	 * @param ctx
	 *            {@link ConnectorContext}
	 * @param response
	 *            HTTP Response
	 * @return true if arcor returns success
	 * @throws Exception
	 *             if an Error occures
	 */
	private boolean afterSmsSent(final ConnectorContext ctx,
			final HttpResponse response) throws Exception {

		String body = Utils.stream2str(response.getEntity().getContent());

		Log.d(TAG, body);

		if (body == null) {
			throw new WebSMSException(ctx.getContext().getString(
					R.string.log_unknow_status_after_send));
		}
		
		
		
		String msg = null;
		if (body.equals("success\n") ) {
			login(ctx);
			return true;
		}
		Context c = ctx.getContext();
		 
		if(body.equals("not_enough_credit\n")){
			body = c.getString(R.string.sms_response_not_enough_credit);
		} else if (body.equals("max_messages\n")){
			body = c.getString(R.string.sms_response_max_messages);
		} else if (body.equals("max_recipients\n")){
			body = c.getString(R.string.sms_response_max_recipients);
		} else if (body.equals("not_enough_money\n")){
			body = c.getString(R.string.sms_response_not_enough_money);
		} else if(body.equals("incorrect_mobile\n")){
			body = c.getString(R.string.sms_response_incorrect_mobile);
		} else {
			body = msg;
		}

		throw new WebSMSException(body);
	}

	/**
	 * Push SMS Free Count to WebSMS.
	 * 
	 * @param ctx
	 *            {@link ConnectorContext}
	 * @param content
	 *            conten to investigate.
	 */
	private void notifyFreeCount(final ConnectorContext ctx,
			final String content) {
		final Matcher m = BALANCE_MATCH_PATTERN.matcher(content);
		String term = null;
		if (m.find()) {
			if (m.groupCount() != 2) {
				term = "?";
			} else {
				term = m.group(1) + "+" + m.group(2) + "ლ";
			}
		} else {
			Log.w(TAG, content);
			term = "?";
		}
		this.getSpec(ctx.getContext()).setBalance(term);
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	protected final void doSend(final Context context, final Intent intent)
			throws WebSMSException {
		final ConnectorContext ctx = ConnectorContext.create(context, intent);
		if (this.login(ctx)) {
			this.sendSms(ctx);
		}

	}
}
