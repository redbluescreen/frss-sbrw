package com.soapboxrace.core.api;

import com.soapboxrace.core.api.util.Secured;
import com.soapboxrace.core.bo.AnalyticsBO;
import com.soapboxrace.core.bo.TokenSessionBO;
import com.soapboxrace.core.jpa.UserEntity;

import javax.ejb.EJB;
import javax.ws.rs.HeaderParam;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.MediaType;

@Path("/heartbeat")
public class HeartBeat {

	@EJB
	private TokenSessionBO sessionBO;

	@EJB
	private AnalyticsBO analyticsBO;

	@POST
	@Secured
	@Produces(MediaType.APPLICATION_XML)
	public com.soapboxrace.jaxb.http.HeartBeat getPermanentSession(@HeaderParam("securityToken") String securityToken, @HeaderParam("userId") Long userId) {
		UserEntity user = sessionBO.getUser(securityToken);
		analyticsBO.sendEvent("Heartbeat", "Heartbeat", user);

		com.soapboxrace.jaxb.http.HeartBeat heartBeat = new com.soapboxrace.jaxb.http.HeartBeat();
		heartBeat.setEnabledBitField(0);
		heartBeat.setMetagameFlags(2);
		return heartBeat;
	}
}
