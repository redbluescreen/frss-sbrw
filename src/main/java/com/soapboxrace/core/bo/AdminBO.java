package com.soapboxrace.core.bo;

import com.soapboxrace.core.api.util.MiscUtils;
import com.soapboxrace.core.dao.BanDAO;
import com.soapboxrace.core.dao.PersonaDAO;
import com.soapboxrace.core.dao.UserDAO;
import com.soapboxrace.core.jpa.BanEntity;
import com.soapboxrace.core.jpa.PersonaEntity;
import com.soapboxrace.core.jpa.UserEntity;
import com.soapboxrace.core.xmpp.OpenFireSoapBoxCli;
import com.soapboxrace.core.xmpp.XmppChat;

import javax.ejb.EJB;
import javax.ejb.Stateless;
import javax.ws.rs.client.ClientBuilder;
import javax.ws.rs.client.Entity;
import javax.ws.rs.core.MediaType;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

@Stateless
public class AdminBO {
	@EJB
	private TokenSessionBO tokenSessionBo;

	@EJB
	private PersonaDAO personaDao;

	@EJB
	private UserDAO userDao;

	@EJB
	private BanDAO banDAO;

	@EJB
	private OpenFireSoapBoxCli openFireSoapBoxCli;

	@EJB
	private ParameterBO parameterBO;

	public String sendChatCommand(Long personaId, String command)
	{
		String response = processChatCommand(personaId, command);
		if (response != null) {
			openFireSoapBoxCli.send(XmppChat.createSystemMessage(response), personaId);
		}
		return response;
	}

	private String processChatCommand(Long personaId, String command)
	{
		CommandInfo commandInfo = CommandInfo.parse(command, true);
		if (commandInfo == null) return null;

		PersonaEntity personaEntity = personaDao.findByName(commandInfo.personaName);
		if (personaEntity == null) return "Cannot find the user!";

		switch (commandInfo.action)
		{
			case BAN:
				if (banDAO.findByUser(personaEntity.getUser()) != null) {
					return "User is already banned!";
				}

				sendBan(personaEntity, personaDao.findById(personaId), commandInfo.timeEnd, commandInfo.reason);
				return "Banned user!";
			case KICK:
				sendKick(personaEntity.getUser().getId(), personaEntity.getPersonaId());
				return "Kicked user!";
			case UNBAN:
				BanEntity existingBan;
				if ((existingBan = banDAO.findByUser(personaEntity.getUser())) == null) {
					return "User is not banned!";
				}

				banDAO.delete(existingBan);
				return "Unbanned user!";
			default:
				return null;
		}
	}

	private void sendBan(PersonaEntity personaEntity, PersonaEntity bannedBy, LocalDateTime endsOn, String reason)
	{
		UserEntity userEntity = personaEntity.getUser();
		BanEntity banEntity = new BanEntity();
		banEntity.setUserEntity(userEntity);
		banEntity.setEndsAt(endsOn);
		banEntity.setStarted(LocalDateTime.now());
		banEntity.setReason(reason);
		banEntity.setBannedBy(bannedBy);
		banEntity.setHwid(userEntity.getGameHardwareHash());
		banEntity.setIp(userEntity.getIpAddress());
		banDAO.insert(banEntity);
		sendKick(userEntity.getId(), personaEntity.getPersonaId());
		banWebhook(banEntity, personaEntity);
	}

	private void sendKick(Long userId, Long personaId)
	{
		openFireSoapBoxCli.send("<NewsArticleTrans><ExpiryTime><", personaId);
		tokenSessionBo.deleteByUserId(userId);
	}

	private void banWebhook(BanEntity banEntity, PersonaEntity personaEntity) {
		if (parameterBO.getStrParam("BAN_WEBHOOK") == null) {
			return;
		}
		Map<String, Object> field1 = new HashMap<>();
		field1.put("name", "Player");
		field1.put("value", personaEntity.getName());
		field1.put("inline", true);

		Map<String, Object> field2 = new HashMap<>();
		field2.put("name", "Reason");
		field2.put("value", banEntity.getReason());
		field1.put("inline", true);

		Map<String, Object> embed = new HashMap<>();
		embed.put("title", ":hammer: Player banned");
		embed.put("color", 0xff0000);
		ZonedDateTime zonedDateTime = banEntity.getStarted().atZone(ZoneId.systemDefault());
		embed.put("timestamp", zonedDateTime.format(DateTimeFormatter.ISO_OFFSET_DATE_TIME));
		embed.put("fields", Arrays.asList(field1, field2));

		Map<String, Object> map = new HashMap<>();
		map.put("embeds", Collections.singletonList(embed));
		ClientBuilder.newClient()
				.target(parameterBO.getStrParam("BAN_WEBHOOK"))
				.request(MediaType.APPLICATION_JSON_TYPE)
				.post(Entity.json(map));
	}

	private static class CommandInfo
	{
		public CommandInfo.CmdAction action;
		public String reason;
		public LocalDateTime timeEnd;
		public String personaName;

		public enum CmdAction
		{
			KICK,
			BAN,
			UNBAN
		}

		public static CommandInfo parse(String cmd, boolean withName)
		{
			cmd = cmd.replaceFirst("/", "").trim();

			String[] splits = cmd.split(" ");
			if (splits.length == 0) return null;

			CommandInfo.CmdAction action;
			CommandInfo info = new CommandInfo();

			switch (splits[0].toLowerCase())
			{
				case "ban":
					action = CmdAction.BAN;
					break;
				case "kick":
					action = CmdAction.KICK;
					break;
				case "unban":
					action = CmdAction.UNBAN;
					break;
				default:
					return null;
			}

			info.action = action;
			info.personaName = splits[1];

			switch (action)
			{
				case BAN:
				{
					LocalDateTime endTime;
					String reason = null;

					if (splits.length > 2)
					{
						long givenTime = MiscUtils.lengthToMiliseconds(splits[2]);
						if (givenTime != 0)
						{
							endTime = LocalDateTime.now().plusSeconds(givenTime / 1000);
							info.timeEnd = endTime;

							if (splits.length > 3)
							{
								reason = MiscUtils.argsToString(splits, 3, splits.length);
							}
						} else
						{
							reason = MiscUtils.argsToString(splits, 2, splits.length);
						}
					}

					info.reason = reason;
					break;
				}
			}

			return info;
		}
	}
}