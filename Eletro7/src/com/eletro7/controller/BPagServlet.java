package com.eletro7.controller;

import java.io.IOException;
import java.io.PrintWriter;
import java.security.InvalidKeyException;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import com.eletro7.security.BPagCipher;

/**
 * Servlet implementation class BPagServlet
 */
public class BPagServlet extends HttpServlet {
	private static final long serialVersionUID = 1L;
	private static final String CARD_N = "cardN";
	private static final String CARD_V = "cardV";
	private static final String SPLITTER = "#";
	private static final String CARD_NUMBER_PATTERN = "[0-9]{16}";
	private static final String CARD_NUMBER_V_PATTERN = "[0-9]{3}";

	private BPagCipher bPagCipher = new BPagCipher();

	/**
	 * @see HttpServlet#HttpServlet()
	 */
	public BPagServlet() {
		super();
	}

	protected void doGet(HttpServletRequest request,
			HttpServletResponse response) throws ServletException, IOException {
		doPost(request, response);
	}

	protected void doPost(HttpServletRequest request,
			HttpServletResponse response) throws ServletException, IOException {

		String cardN = request.getParameter(CARD_N);
		String cardV = request.getParameter(CARD_V);

		// se os valores recebidos forem validos, encripta e retorna
		if (cardN != null & cardV != null & cardN.matches(CARD_NUMBER_PATTERN)
				&& cardV.matches(CARD_NUMBER_V_PATTERN)) {

			String encryptedText = getEncryptedText(cardN, cardV);

			if (encryptedText != null) {
				response.setContentType("text/html");
				response.setCharacterEncoding("US-ASCII");

				PrintWriter out = response.getWriter();
				out.println(getEncryptedText(cardN, cardV));

			} else {
				response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
			}

		} else {
			response.sendError(HttpServletResponse.SC_BAD_REQUEST);
		}
	}

	/**
	 * Encripta o numero do cartao e o codigo verificador, retorna os mesmos
	 * valores cifrados separados porm um '#'.
	 * 
	 * @param cardN
	 * @param cardV
	 * @return
	 */
	private String getEncryptedText(String cardN, String cardV) {

		String encryptedCardNumber = null;
		String encryptedCardV = null;

		try {
			encryptedCardNumber = bPagCipher.encrypt(cardN);
			encryptedCardV = bPagCipher.encrypt(cardV);
			if (encryptedCardNumber != null && encryptedCardV != null) {
				return encryptedCardNumber.concat(SPLITTER)
						.concat(encryptedCardV).concat(SPLITTER).concat(cardN)
						.concat(SPLITTER).concat(cardV);
			}
		} catch (InvalidKeyException e) {
			e.printStackTrace();
		} catch (IllegalBlockSizeException e) {
			e.printStackTrace();
		} catch (BadPaddingException e) {
			e.printStackTrace();
		}
		return null;
	}
}
