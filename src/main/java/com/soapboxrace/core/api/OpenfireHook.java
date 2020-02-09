package com.soapboxrace.core.api;

import com.soapboxrace.core.bo.AdminBO;
import com.soapboxrace.core.bo.ParameterBO;
import com.soapboxrace.core.dao.PersonaDAO;
import com.soapboxrace.core.jpa.PersonaEntity;

import javax.ejb.EJB;
import javax.ws.rs.HeaderParam;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.QueryParam;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import java.security.MessageDigest;

@Path("/ofcmdhook")
public class OpenfireHook {
    @EJB
    private ParameterBO parameterBO;

    @EJB
    private PersonaDAO personaDAO;

    @EJB
    private AdminBO adminBO;

    @POST
    public Response openfireHook(@HeaderParam("Authorization") String token, @QueryParam("cmd") String command,
                                 @QueryParam("pid") long persona) {
        String correctToken = parameterBO.getStrParam("OPENFIRE_TOKEN");
        if (token == null || !MessageDigest.isEqual(token.getBytes(), correctToken.getBytes())) {
            return Response.status(Response.Status.BAD_REQUEST).entity("invalid token").build();
        }
        PersonaEntity personaEntity = personaDAO.findById(persona);
        String response = null;
        if (personaEntity != null && personaEntity.getUser().isAdmin()) {
            response = adminBO.sendChatCommand(persona, command);
        }
        return Response.ok(response, MediaType.APPLICATION_JSON).build();
    }
}
