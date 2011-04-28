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
package org.herrlado.websms.connector.magtifun;

import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.util.HashMap;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.apache.http.HttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.client.utils.URLEncodedUtils;
import org.apache.http.entity.StringEntity;
import org.apache.http.message.BasicHeader;
import org.apache.http.protocol.HTTP;

import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.preference.PreferenceManager;
import android.util.Log;
import de.ub0r.android.websms.connector.common.Connector;
import de.ub0r.android.websms.connector.common.ConnectorSpec;
import de.ub0r.android.websms.connector.common.Utils;
import de.ub0r.android.websms.connector.common.WebSMSException;

/**
 * Receives commands coming as broadcast from WebSMS.
 * 
 * @author flx
 */
public class ConnectorMagtifun extends Connector {
	/** Tag for debug output. */
	private static final String TAG = "WebSMS.magtifun.ge";

	/** Login URL, to send Login (POST). */
	private static final String LOGIN_URL = "http://www.magtifun.ge/index.php?action=login";

	/** Send SMS URL(POST) / Free SMS Count URL(GET). */
	private static final String SMS_URL = "http://www.magtifun.ge/index.php?step=41";

	/** Encoding to use. */
	private static final String ENCODING = "UTF-8";

	/** HTTP Header User-Agent. */
	private static final String FAKE_USER_AGENT = "Mozilla/5.0 (Windows; U;"
			+ " Windows NT 5.1; de; rv:1.9.0.9) Gecko/2009040821"
			+ " Firefox/3.0.9 (.NET CLR 3.5.30729)";

	/** This String will be matched if the user is logged in. */
	private static final String MATCH_LOGIN_SUCCESS = "logout2.gif";

	private static final String RESTRICTED_OPERATOR = "მოცემული მობილური ოპერატორის ქსელში შეტყობინების გაგზავნა შეზღუდულია";

	private static final String WRONG_RECIPIENT = "ადრესატის ნომერი არასწორადაა შეყვანილი";

	private static final String SEND_OK = "შეტყობინება გაგზავნილია ნომერზე";

	/**
	 * Pattern to extract free sms count from sms page. Looks like.
	 */
	private static final Pattern BALANCE_MATCH_PATTERN = Pattern.compile(
			"<B>უფასო SMS-კრედიტი: (\\d{1,})</B>", Pattern.DOTALL);

	private static final String SEND_CHECK_STATUS_PATTERN = "შეტყობინება გაგზავნილია ნომერზე";

	private static final String PAGE_ENCODING = "UTF-8";

	private static final HashMap<String, String> codes = new HashMap<String, String>();

	private static final String DEFAULT_CODE = "4";

	static {
		codes.put("99", "1");
		codes.put("95", "6");
		codes.put("91", "11");
		codes.put("98", "5");
		codes.put("96", "15");
		codes.put("77", "2");
		codes.put("93", "3");
		codes.put("55", "7");
		codes.put("58", "8");
		codes.put("57", "14");
		codes.put("97", "8");
		codes.put("79", "10");
		codes.put("71", "12");
		codes.put("74", "13");
	}

	// public ConnectorMyphone() {
	// Log.w(TAG, "ConnectorMyphone");
	// }

	/**
	 * {@inheritDoc}
	 */
	@Override
	public final ConnectorSpec initSpec(final Context context) {
		final String name = context.getString(R.string.myphone_name);
		final ConnectorSpec c = new ConnectorSpec(TAG, name);
		c.setAuthor(// .
				context.getString(R.string.myphone_author));
		c.setBalance(null);
		c.setPrefsTitle(context.getString(R.string.preferences));

		c.setCapabilities(ConnectorSpec.CAPABILITIES_UPDATE
				| ConnectorSpec.CAPABILITIES_SEND
				| ConnectorSpec.CAPABILITIES_PREFS);
		c.addSubConnector(TAG, c.getName(), 0);

		// c.setCapabilities(ConnectorSpec.CAPABILITIES_UPDATE
		// | ConnectorSpec.CAPABILITIES_SEND
		// | ConnectorSpec.CAPABILITIES_PREFS);
		// c.addSubConnector(TAG, c.getName(),
		// SubConnectorSpec.FEATURE_MULTIRECIPIENTS
		// | SubConnectorSpec.FEATURE_CUSTOMSENDER
		// | SubConnectorSpec.FEATURE_SENDLATER);
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
		sb.append("login=");
		 sb.append(URLEncoder.encode(username, ENCODING));
		sb.append("&passwd=");
		 sb.append(URLEncoder.encode(password, ENCODING));
		// sb.append("");
		sb.append("&remember=1");
		// sb
		// .append("&login=Login&protocol="
		// + "https&info=Online-Passwort&goto=");
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
		final SharedPreferences p = ctx.getPreferences();
		final StringBuilder sb = new StringBuilder();
		final String[] to = ctx.getCommand().getRecipients();
		// for (final String r : to) {
		// sb.append(r).append(",");
		// }
		final StringBuilder sb1 = new StringBuilder();

		final String number = Utils.getRecipientsNumber(to[0]);
		String codeOption = null;
		String code = null;
		final String tomobile = null;
		if (number.startsWith("8")) {
			code = number.substring(1, 3);
			codeOption = codes.get(code);
		} else if (number.startsWith("00995")) {
			code = number.substring(4, 6);
			codeOption = codes.get(code);

		} else if (number.startsWith("+995")) {
			code = number.substring(3, 5);
			codeOption = codes.get(code);

		} else {
			code = DEFAULT_CODE;
			codeOption = DEFAULT_CODE;
		}

		if (codeOption == null) {
			throw new WebSMSException("Unknown code: " + code);
		}

		sb1.append("tomobile=").append(tomobile);
		sb1.append("&code=").append(code);
		sb1.append("&frommobile=");
		sb1.append("&smscode=NOCODE");
		sb1.append("&smstext=");
		sb1
				.append(URLEncoder.encode("test, tu mova visgan mova aba",
						ENCODING));
		// // sb1.append(URLEncoder.encode(sb.toString(), PAGE_ENCODING));
		// sb1.append(URLEncoder.encode("+4917640232695,", PAGE_ENCODING));
		//
		// String sender = Utils.getSender(ctx.getContext(), ctx.getCommand()
		// .getDefSender());
		// sender = URLEncoder.encode(sender, PAGE_ENCODING);
		// sender = "4917640232695";
		// // sb1.append("&mobnum=").append(sender);
		// // sb1.append("&oadc=").append(sender);
		// sb1.append("&anum=").append(sender);
		//
		// sb1.append("&msg=");
		// sb1
		// .append(URLEncoder.encode(ctx.getCommand().getText(),
		// PAGE_ENCODING));
		// final long sendLater = ctx.getCommand().getSendLater();
		// // if (sendLater <= 0) {
		// sb1.append("&schedule=").append("now");
		// // } else {
		// final Calendar cal = Calendar.getInstance();
		// cal.setTimeInMillis(sendLater);
		//
		// // }
		//
		// // sb1.append("&sendsms=true");
		// // sb1.append("&empfcount=1");
		// // sb1.append("&preheader=");
		// sb1.append("&acccode=423408");
		// sb1.append("&pass=6fcbe8933378176a246b4accbdea46ca");
		// sb1.append("&webpass=6fcbe8933378176a246b4accbdea46ca");
		// // sb1.append("&webpass=");

		return sb1.toString();
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
			final HttpPost request = createPOST(LOGIN_URL, getLoginPost(p
					.getString(Preferences.USERNAME, ""), p.getString(
					Preferences.PASSWORD, "")));
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
	private void updateBalance(final ConnectorContext ctx)
			throws WebSMSException {
		try {
			final HttpResponse response = ctx.getClient().execute(
					new HttpGet(SMS_URL));
			this.notifyFreeCount(ctx, Utils.stream2str(response.getEntity()
					.getContent()));

		} catch (final Exception ex) {
			throw new WebSMSException(ex.getMessage());
		}
	}

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

		final String body = Utils.stream2str(response.getEntity().getContent());

		final boolean sent = body.contains(SEND_CHECK_STATUS_PATTERN);
		if (!sent) {
			// should not happen
			Log.w(TAG, body);
			throw new Exception(ctx.getContext().getString(
					R.string.log_unknow_status_after_send));
		}

		// TODO hier activation handling
		return true;

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
			term = m.group(1);
			// } else if (content.contains(MATCH_NO_SMS)) {
			// term = "0+0";
			// } else if (content.contains(MATCH_UNLIMITTED_SMS)) {
			// term = "\u221E";
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
