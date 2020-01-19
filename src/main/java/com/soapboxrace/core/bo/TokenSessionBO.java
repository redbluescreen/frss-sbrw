package com.soapboxrace.core.bo;

import com.google.common.hash.Hashing;
import com.soapboxrace.core.api.util.GeoIp2;
import com.soapboxrace.core.api.util.UUIDGen;
import com.soapboxrace.core.bo.util.PwnedPasswords;
import com.soapboxrace.core.dao.TokenSessionDAO;
import com.soapboxrace.core.dao.UserDAO;
import com.soapboxrace.core.jpa.BanEntity;
import com.soapboxrace.core.jpa.PersonaEntity;
import com.soapboxrace.core.jpa.TokenSessionEntity;
import com.soapboxrace.core.jpa.UserEntity;
import com.soapboxrace.jaxb.*;
import com.soapboxrace.jaxb.login.LoginStatusVO;

import javax.ejb.EJB;
import javax.ejb.Stateless;
import javax.servlet.http.HttpServletRequest;
import javax.ws.rs.NotAuthorizedException;
import javax.ws.rs.client.ClientBuilder;
import javax.ws.rs.client.Entity;
import javax.ws.rs.core.MediaType;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.time.format.FormatStyle;
import java.util.Base64;
import java.util.Date;

@Stateless
public class TokenSessionBO {
	@EJB
	private TokenSessionDAO tokenDAO;

	@EJB
	private UserDAO userDAO;

	@EJB
	private ParameterBO parameterBO;

	@EJB
	private GetServerInformationBO serverInfoBO;

	@EJB
	private AuthenticationBO authenticationBO;

	@EJB
	private Argon2BO argon2;

	@EJB
	private AnalyticsBO analyticsBO;

	public boolean verifyToken(Long userId, String securityToken) {
		TokenSessionEntity tokenSessionEntity = tokenDAO.findById(securityToken);
		if (tokenSessionEntity == null || !tokenSessionEntity.getUserId().equals(userId)) {
			return false;
		}
		long time = new Date().getTime();
		long tokenTime = tokenSessionEntity.getExpirationDate().getTime();
		if (time > tokenTime) {
			return false;
		}
		tokenSessionEntity.setExpirationDate(getMinutes(3));
		tokenDAO.update(tokenSessionEntity);
		return true;
	}

	public void updateToken(String securityToken) {
		TokenSessionEntity tokenSessionEntity = tokenDAO.findById(securityToken);
		Date expirationDate = getMinutes(3);
		tokenSessionEntity.setExpirationDate(expirationDate);
		tokenDAO.update(tokenSessionEntity);
	}

	public String createToken(Long userId, String clientHostName) {
		TokenSessionEntity tokenSessionEntity = new TokenSessionEntity();
		Date expirationDate = getMinutes(15);
		tokenSessionEntity.setExpirationDate(expirationDate);
		String randomUUID = UUIDGen.getRandomUUID();
		tokenSessionEntity.setSecurityToken(randomUUID);
		tokenSessionEntity.setUserId(userId);
		UserEntity userEntity = userDAO.findById(userId);
		tokenSessionEntity.setPremium(userEntity.isPremium());
		tokenSessionEntity.setClientHostIp(clientHostName);
		tokenSessionEntity.setActivePersonaId(0L);
		tokenDAO.insert(tokenSessionEntity);
		return randomUUID;
	}

	public boolean verifyPersona(String securityToken, Long personaId) {
		TokenSessionEntity tokenSession = tokenDAO.findById(securityToken);
		if (tokenSession == null) {
			throw new NotAuthorizedException("Invalid session...");
		}

		UserEntity user = userDAO.findById(tokenSession.getUserId());
		if (!user.ownsPersona(personaId)) {
			throw new NotAuthorizedException("Persona is not owned by user");
		}
		return true;
	}

	public void deleteByUserId(Long userId) {
		TokenSessionEntity token = tokenDAO.findByUserId(userId);
		if (token != null) {
			if (token.getCryptoTicket() != null) {
				revokeCryptoTicket(token.getCryptoTicket());
			}
			tokenDAO.deleteByUserId(userId);
		}
	}

	private Date getMinutes(int minutes) {
		long time = new Date().getTime();
		time = time + (minutes * 60000);
		Date date = new Date(time);
		return date;
	}

	public LoginStatusVO checkGeoIp(String ip) {
		LoginStatusVO loginStatusVO = new LoginStatusVO(0L, "", false);
		String allowedCountries = serverInfoBO.getServerInformation().getAllowedCountries();
		if (allowedCountries != null && !allowedCountries.isEmpty()) {
			String geoip2DbFilePath = parameterBO.getStrParam("GEOIP2_DB_FILE_PATH");
			GeoIp2 geoIp2 = GeoIp2.getInstance(geoip2DbFilePath);
			if (geoIp2.isCountryAllowed(ip, allowedCountries)) {
				return new LoginStatusVO(0L, "", true);
			} else {
				loginStatusVO.setDescription("GEOIP BLOCK ACTIVE IN THIS SERVER, ALLOWED COUNTRIES: [" + allowedCountries + "]");
			}
		} else {
			return new LoginStatusVO(0L, "", true);
		}
		return loginStatusVO;
	}

	public LoginStatusVO login(String email, String password, HttpServletRequest httpRequest) {
		if (parameterBO.getBoolParam("LEGACY_AUTH_DISABLE")) {
			LoginStatusVO loginStatusVO = new LoginStatusVO(0L, "", false);
			loginStatusVO.setDescription("This server requires launcher with Modern Auth support.");
			return loginStatusVO;
		}

		LoginStatusVO loginStatusVO = checkGeoIp(httpRequest.getRemoteAddr());
		if (!loginStatusVO.isLoginOk()) {
			return loginStatusVO;
		}
		loginStatusVO = new LoginStatusVO(0L, "", false);

		if (email != null && !email.isEmpty() && password != null && !password.isEmpty()) {
			UserEntity userEntity = userDAO.findByEmail(email);
			if (userEntity != null) {
				if (password.equals(userEntity.getPassword())) {
					userEntity.setIpAddress(httpRequest.getRemoteAddr());
					BanEntity banEntity = authenticationBO.checkUserBan(userEntity);

					if (banEntity != null) {
						LoginStatusVO.Ban ban = new LoginStatusVO.Ban();
						ban.setReason(banEntity.getReason());
						if (banEntity.getEndsAt() != null)
							ban.setExpires(DateTimeFormatter.ofLocalizedDateTime(FormatStyle.FULL).withZone(ZoneId.systemDefault()).format(banEntity.getEndsAt()));
						loginStatusVO.setBan(ban);
						return loginStatusVO;
					}

					userEntity.setLastLogin(LocalDateTime.now());
					String xUA = httpRequest.getHeader("X-User-Agent");
					userEntity.setUserAgent(xUA != null ? xUA : httpRequest.getHeader("User-Agent"));
					userDAO.update(userEntity);
					analyticsBO.trackUserLogin(userEntity);

					Long userId = userEntity.getId();
					deleteByUserId(userId);
					String randomUUID = createToken(userId, null);
					loginStatusVO = new LoginStatusVO(userId, randomUUID, true);
					loginStatusVO.setDescription("");

					int breachCount = PwnedPasswords.checkHash(password);
					if (breachCount > 0) {
						loginStatusVO.setWarning("Your password has been breached " + breachCount + " times and should never be used.\nPlease choose new password using the password reset functionality.");
					}

					return loginStatusVO;
				}
			}
		}
		loginStatusVO.setDescription("LOGIN ERROR");
		return loginStatusVO;
	}

	public ModernAuthResponse modernLogin(String email, String password, boolean upgrade, HttpServletRequest request) throws AuthException {
		if (parameterBO.getBoolParam("MODERN_AUTH_DISABLE")) {
			throw new AuthException("Modern Auth not enabled!");
		}

		UserEntity userEntity = userDAO.findByEmail(email);
		if (userEntity == null) {
			throw new AuthException("Invalid username or password");
		}
		if (userEntity.getVerifyToken() != null) {
			throw new AuthException("Email not verified");
		}
		if (userEntity.getPassword().length() == 40) {
			@SuppressWarnings("deprecation")
			String legacyHash = Hashing.sha1().hashString(password, StandardCharsets.UTF_8).toString();
			if (!legacyHash.equals(userEntity.getPassword())) {
				throw new AuthException("Invalid username or password");
			}

            if (upgrade) {
                String hash = argon2.hash(password);
                userEntity.setPassword(hash);
            }
		} else {
			if (!argon2.verify(userEntity.getPassword(), password)) {
				throw new AuthException("Invalid username or password");
			}
		}

		userEntity.setIpAddress(request.getHeader("X-Forwarded-For"));
        BanEntity banEntity = authenticationBO.checkUserBan(userEntity);

        if (banEntity != null) {
            StringBuilder sb = new StringBuilder();
            sb.append("Your account has been banned");
            if (banEntity.getEndsAt() != null) {
                sb.append(" until ");
                sb.append(DateTimeFormatter.ofLocalizedDateTime(FormatStyle.FULL).withZone(ZoneId.systemDefault()).format(banEntity.getEndsAt()));
            }
            if (banEntity.getReason() != null) {
                sb.append('\n');
                sb.append("Reason: ");
                sb.append(banEntity.getReason());
            }
            throw new AuthException(sb.toString());
        }

		userEntity.setLastLogin(LocalDateTime.now());
        String xUA = request.getHeader("X-User-Agent");
        userEntity.setUserAgent(xUA != null ? xUA : request.getHeader("User-Agent"));
		userDAO.update(userEntity);
		analyticsBO.trackUserLogin(userEntity);

		ModernAuthResponse response = new ModernAuthResponse();
		Long userId = userEntity.getId();
		deleteByUserId(userId);
		String randomUUID = createToken(userId, null);
		response.setUserId(userId);
		response.setToken(randomUUID);

		int breachCount = PwnedPasswords.checkPassword(password);
		if (breachCount > 0) {
			response.setWarning("Your password has been breached " + breachCount + " times and should never be used.\nPlease choose new password using the password reset functionality.");
		}

		return response;
	}

	public Long getActivePersonaId(String securityToken) {
		TokenSessionEntity tokenSessionEntity = tokenDAO.findById(securityToken);
		return tokenSessionEntity.getActivePersonaId();
	}

	public void setActivePersonaId(String securityToken, Long personaId, Boolean isLogout) {
		TokenSessionEntity tokenSessionEntity = tokenDAO.findById(securityToken);

		if (!isLogout) {
			if (!userDAO.findById(tokenSessionEntity.getUserId()).ownsPersona(personaId)) {
				throw new NotAuthorizedException("Persona not owned by user");
			}
		}

		tokenSessionEntity.setActivePersonaId(personaId);
		tokenDAO.update(tokenSessionEntity);
	}

	public String getActiveRelayCryptoTicket(String securityToken) {
		TokenSessionEntity tokenSessionEntity = tokenDAO.findById(securityToken);
		return tokenSessionEntity.getRelayCryptoTicket();
	}

	public Long getActiveLobbyId(String securityToken) {
		TokenSessionEntity tokenSessionEntity = tokenDAO.findById(securityToken);
		return tokenSessionEntity.getActiveLobbyId();
	}

	public void setActiveLobbyId(String securityToken, Long lobbyId) {
		TokenSessionEntity tokenSessionEntity = tokenDAO.findById(securityToken);
		tokenSessionEntity.setActiveLobbyId(lobbyId);
		tokenDAO.update(tokenSessionEntity);
	}

	public String getCryptoTicket(String securityToken) {
		if (!parameterBO.getBoolParam("FREEROAM_TS_ENABLED")) {
			ByteBuffer byteBuffer = ByteBuffer.allocate(32);
			byteBuffer.put(new byte[] { 10, 11, 12, 13 });
			byte[] cryptoTicketBytes = byteBuffer.array();
			return Base64.getEncoder().encodeToString(cryptoTicketBytes);
		}
		TokenSessionEntity token = tokenDAO.findById(securityToken);
		if (token.getCryptoTicket() != null) {
			return token.getCryptoTicket();
		}
		UserEntity user = userDAO.findById(token.getUserId());
		TSTicketRequest req = new TSTicketRequest();
		for (PersonaEntity persona : user.getListOfProfile()) {
			req.addPersona(persona.getPersonaId());
		}
		TSTicketResponse res = ClientBuilder.newClient()
				.target(parameterBO.getStrParam("FREEROAM_TS_ENDPOINT"))
				.path("/api/v1/tickets/request")
				.request(MediaType.APPLICATION_JSON_TYPE)
				.header("Authorization", "Bearer " + parameterBO.getStrParam("FREEROAM_TS_APIKEY"))
				.post(Entity.json(req), TSTicketResponse.class);
		token.setCryptoTicket(res.getTicket());
		tokenDAO.update(token);
		return res.getTicket();
	}

	public void revokeCryptoTicket(String ticket) {
		if (!parameterBO.getBoolParam("FREEROAM_TS_ENABLED")) return;
		TSRevokeRequest req = new TSRevokeRequest(ticket);
		ClientBuilder.newClient()
				.target(parameterBO.getStrParam("FREEROAM_TS_ENDPOINT"))
				.path("/api/v1/tickets/revoke")
				.request(MediaType.APPLICATION_JSON_TYPE)
				.header("Authorization", "Bearer " + parameterBO.getStrParam("FREEROAM_TS_APIKEY"))
				.post(Entity.json(req));
	}

	public boolean isPremium(String securityToken) {
		return tokenDAO.findById(securityToken).isPremium();
	}

	public boolean isAdmin(String securityToken) {
		return getUser(securityToken).isAdmin();
	}

	public UserEntity getUser(String securityToken) {
		return userDAO.findById(tokenDAO.findById(securityToken).getUserId());
	}
}
