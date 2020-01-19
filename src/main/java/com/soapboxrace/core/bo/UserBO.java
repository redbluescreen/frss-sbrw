package com.soapboxrace.core.bo;

import com.google.common.base.Charsets;
import com.google.common.io.BaseEncoding;
import com.google.common.io.Resources;
import com.soapboxrace.core.dao.InviteTicketDAO;
import com.soapboxrace.core.dao.ServerInfoDAO;
import com.soapboxrace.core.dao.UserDAO;
import com.soapboxrace.core.jpa.InviteTicketEntity;
import com.soapboxrace.core.jpa.PersonaEntity;
import com.soapboxrace.core.jpa.UserEntity;
import com.soapboxrace.core.xmpp.OpenFireRestApiCli;
import com.soapboxrace.jaxb.AuthException;
import com.soapboxrace.jaxb.http.ArrayOfProfileData;
import com.soapboxrace.jaxb.http.ProfileData;
import com.soapboxrace.jaxb.http.User;
import com.soapboxrace.jaxb.http.UserInfo;
import com.soapboxrace.jaxb.login.LoginStatusVO;

import javax.annotation.Resource;
import javax.ejb.EJB;
import javax.ejb.Stateless;
import javax.mail.Message;
import javax.mail.MessagingException;
import javax.mail.Session;
import javax.mail.Transport;
import javax.mail.internet.AddressException;
import javax.mail.internet.InternetAddress;
import javax.mail.internet.MimeMessage;
import javax.servlet.http.HttpServletRequest;
import java.io.IOException;
import java.security.SecureRandom;
import java.time.LocalDateTime;
import java.util.List;

@Stateless
public class UserBO {

	@EJB
	private UserDAO userDao;

	@EJB
	private InviteTicketDAO inviteTicketDAO;

	@EJB
	private ServerInfoDAO serverInfoDAO;

	@EJB
	private OpenFireRestApiCli xmppRestApiCli;

	@EJB
	private ParameterBO parameterBO;

	@EJB
	private Argon2BO argon2;

	@EJB
	private AnalyticsBO analyticsBO;

	@Resource(mappedName = "java:jboss/mail/Gmail")
	private Session mailSession;

	public void createXmppUser(UserInfo userInfo) {
		String securityToken = userInfo.getUser().getSecurityToken();
		String xmppPasswd = securityToken.substring(0, 16);
		List<ProfileData> profileData = userInfo.getPersonas().getProfileData();
		for (ProfileData persona : profileData) {
			createXmppUser(persona.getPersonaId(), xmppPasswd);
		}
	}

	public void createXmppUser(Long personaId, String xmppPasswd) {
		xmppRestApiCli.createUpdatePersona(personaId, xmppPasswd);
	}

	private UserEntity createUser(String email, String passwd, boolean setVerifyToken, HttpServletRequest request) {
		UserEntity userEntity = new UserEntity();
		userEntity.setEmail(email);
		userEntity.setPassword(passwd);
		userEntity.setCreated(LocalDateTime.now());
		userEntity.setLastLogin(LocalDateTime.now());
		if (setVerifyToken) {
			byte key[] = new byte[16];
			new SecureRandom().nextBytes(key);
			userEntity.setVerifyToken(BaseEncoding.base16().lowerCase().encode(key));
		}
		 userEntity.setIpAddress(Request.getRemoteAddr());
		String xUA = request.getHeader("X-User-Agent");
		userEntity.setUserAgent(xUA != null ? xUA : request.getHeader("User-Agent"));
		userDao.insert(userEntity);
		analyticsBO.trackUserRegister(userEntity);
		return userEntity;
	}

	public LoginStatusVO createUserWithTicket(String email, String passwd, String ticket, HttpServletRequest request) {
		LoginStatusVO loginStatusVO = new LoginStatusVO(0L, "", false);

		if (parameterBO.getBoolParam("LEGACY_AUTH_DISABLE")) {
			loginStatusVO.setDescription("This server requires launcher with Modern Auth support.");
			return loginStatusVO;
		}

		if(isInvalidEmail(email)) {
			loginStatusVO.setDescription("Registration Error: Invalid Email Format!");
			return loginStatusVO;
		}

		InviteTicketEntity inviteTicketEntity = new InviteTicketEntity();
		inviteTicketEntity.setTicket("empty-ticket");
		String ticketToken = parameterBO.getStrParam("TICKET_TOKEN");
		if (ticketToken != null && !ticketToken.equals("null")) {
			inviteTicketEntity = inviteTicketDAO.findByTicket(ticket);
			if (inviteTicketEntity == null || inviteTicketEntity.getTicket() == null || inviteTicketEntity.getTicket().isEmpty()) {
				loginStatusVO.setDescription("Registration Error: Invalid Ticket!");
				return loginStatusVO;
			}
			if (inviteTicketEntity.getUser() != null) {
				loginStatusVO.setDescription("Registration Error: Ticket already in use!");
				return loginStatusVO;
			}
		}
		UserEntity userEntityTmp = userDao.findByEmail(email);
		if (userEntityTmp != null) {
			if (userEntityTmp.getEmail() != null) {
				loginStatusVO.setDescription("Registration Error: Email already exists!");
				return loginStatusVO;
			}
		}
		boolean verifyEmail = !parameterBO.getBoolParam("DISABLE_EMAIL_VERIFICATION");
		UserEntity userEntity = createUser(email, passwd, verifyEmail, request);
		if (verifyEmail) {
			try {
				sendEmailVerify(email, userEntity.getVerifyToken());
			} catch (Exception e) {
				loginStatusVO.setDescription("Failed to send verification email!");
				return loginStatusVO;
			}
		}
		inviteTicketEntity.setUser(userEntity);
		inviteTicketDAO.insert(inviteTicketEntity);
		serverInfoDAO.updateNumberOfRegistered();
		if (verifyEmail) {
			loginStatusVO.setDescription("Account created! But before logging in, you need to verify your email.");
			return loginStatusVO;
		}
		loginStatusVO = new LoginStatusVO(userEntity.getId(), "", true);
		return loginStatusVO;
	}

	public boolean createModernUser(String email, String password, String ticket, HttpServletRequest request) throws AuthException {
		if (parameterBO.getBoolParam("MODERN_AUTH_DISABLE")) {
			throw new AuthException("Modern Auth not enabled!");
		}

		if(isInvalidEmail(email)) {
			throw new AuthException("Invalid email");
		}

		InviteTicketEntity inviteTicketEntity = null;
		String ticketToken = parameterBO.getStrParam("TICKET_TOKEN");
		if (ticketToken != null && !ticketToken.equals("null")) {
			inviteTicketEntity = inviteTicketDAO.findByTicket(ticket);
			if (inviteTicketEntity == null || inviteTicketEntity.getTicket() == null || inviteTicketEntity.getTicket().isEmpty()) {
				throw new AuthException("Invalid ticket!");
			}
			if (inviteTicketEntity.getUser() != null) {
				throw new AuthException("Ticket already used!");
			}
		}

		UserEntity userEntityTmp = userDao.findByEmail(email);
		if (userEntityTmp != null) {
			if (userEntityTmp.getEmail() != null) {
				throw new AuthException("Email already exists");
			}
		}
		String hash = argon2.hash(password);
		boolean verifyEmail = !parameterBO.getBoolParam("DISABLE_EMAIL_VERIFICATION");
		UserEntity createdUser = createUser(email, hash, verifyEmail, request);
		if (verifyEmail) {
			try {
				sendEmailVerify(email, createdUser.getVerifyToken());
			} catch (Exception e) {
				throw new AuthException("Failed to send verification email!");
			}
		}
		if (inviteTicketEntity != null) {
			inviteTicketEntity.setUser(createdUser);
			inviteTicketDAO.insert(inviteTicketEntity);
		}
		serverInfoDAO.updateNumberOfRegistered();

		return verifyEmail;
	}

	private boolean isInvalidEmail(String email) {
		try {
			InternetAddress address = new InternetAddress(email);
			address.validate();
		} catch (AddressException e) {
			return true;
		}
		String[] splits = email.split("@");
		if (splits[1].equalsIgnoreCase("gmail.com")) {
			return splits[0].length() < 6 || splits[0].length() > 30;
		}
		return false;
	}

	private void sendEmailVerify(String email, String token) throws MessagingException, IOException {
		MimeMessage message = new MimeMessage(mailSession);
		message.setFrom(new InternetAddress(parameterBO.getStrParam("EMAIL_FROM")));
		message.addRecipient(Message.RecipientType.TO, new InternetAddress(email));
		message.setSubject("Verify your email!");
		String body = Resources.toString(Resources.getResource("email_verify.txt"), Charsets.UTF_8);
		body = body.replaceAll("\\{url}", parameterBO.getStrParam("SERVER_ADDRESS") +
				"/soapbox-race-core/Engine.svc/User/verify?token=" + token);
		message.setText(body);
		Transport.send(message);
	}

	public boolean verifyEmail(String token) {
		UserEntity user = userDao.findByVerifyToken(token);
		if (user == null) {
			return false;
		}
		user.setVerifyToken(null);
		userDao.update(user);
		return true;
	}

	public UserInfo secureLoginPersona(Long userId, Long personaId) {
		UserInfo userInfo = new UserInfo();
		userInfo.setPersonas(new ArrayOfProfileData());
		com.soapboxrace.jaxb.http.User user = new com.soapboxrace.jaxb.http.User();
		user.setUserId(userId);
		userInfo.setUser(user);
		return userInfo;
	}

	public UserInfo getUserById(Long userId) {
		UserEntity userEntity = userDao.findById(userId);
		UserInfo userInfo = new UserInfo();
		ArrayOfProfileData arrayOfProfileData = new ArrayOfProfileData();
		List<PersonaEntity> listOfProfile = userEntity.getListOfProfile();
		for (PersonaEntity personaEntity : listOfProfile) {
			// switch to apache beanutils copy
			ProfileData profileData = new ProfileData();
			profileData.setName(personaEntity.getName());
			profileData.setCash(personaEntity.getCash());
			profileData.setBoost(personaEntity.getBoost());
			profileData.setIconIndex(personaEntity.getIconIndex());
			profileData.setPersonaId(personaEntity.getPersonaId());
			profileData.setLevel(personaEntity.getLevel());
			arrayOfProfileData.getProfileData().add(profileData);
		}
		userInfo.setPersonas(arrayOfProfileData);
		User user = new User();
		user.setUserId(userId);
		userInfo.setUser(user);
		return userInfo;
	}

}
