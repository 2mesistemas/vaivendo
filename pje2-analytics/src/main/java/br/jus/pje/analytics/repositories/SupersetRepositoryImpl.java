package br.jus.pje.analytics.repositories;

import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.List;

import org.apache.commons.lang3.StringUtils;
import org.apache.tomcat.util.http.fileupload.ByteArrayOutputStream;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Repository;
import org.springframework.web.client.RestTemplate;

import com.mashape.unirest.http.HttpResponse;
import com.mashape.unirest.http.Unirest;
import com.mashape.unirest.http.exceptions.UnirestException;

import br.jus.pje.analytics.exceptions.AnalyticsException;
import br.jus.pje.analytics.models.Dashboard;

@Repository
public class SupersetRepositoryImpl implements AnalyticsRepository {
  private static final String CSRF_FIELD = "id=\"csrf_token\" name=\"csrf_token\" type=\"hidden\" value=\"";
  private static final String DASHBOARD_FIELD = "<td><a href=\"";
  private static final String COOKIE_HEADER = "Set-Cookie";

  @Value("${analytics.superset.host}")
  private String supersetHost;

  @Value("${analytics.superset.port}")
  private String supersetPort;

  private String urlRaiz;
  private String urlGetDashboards;
  private String urlLogin;
  private String urlSharedDashboard;

  private String dashboardStringFormat = urlRaiz + "r/%s?standalone=true";

  private RestTemplate restTemplate;
  private String cookie = "";
  private Date ultimaChamada = null;

  public SupersetRepositoryImpl(final RestTemplate restTempalte) {
    this.restTemplate = restTempalte;
    if (StringUtils.isNotEmpty(supersetHost)) {
      montaUrlsSuperset();
    }
  }

  @Override
  public List<Dashboard> recuperaDashboards() {
    validaSupersetUrl();
    List<Dashboard> dashboards = new ArrayList<>();
    logIntoSuperset();

    try {
      HttpResponse<String> resposta = Unirest.get(urlGetDashboards)
          .header("Content-Type", MediaType.APPLICATION_JSON_VALUE).header("Cookie", cookie)
          .asString();

      if (resposta.getStatus() == HttpStatus.OK.value()) {
        String body = resposta.getBody();
        dashboards = getDashboardsListFromBody(body);
        cookie = resposta.getHeaders().getFirst(COOKIE_HEADER);
        ultimaChamada = new Date();
      }
    } catch (UnirestException e) {
      throw new AnalyticsException("Error requesting superset dashboards", e);
    }
    return dashboards;
  }

  @Override
  public Dashboard recuperaDashboard(long dashboardId) {
    validaSupersetUrl();
    logIntoSuperset();
    try (ByteArrayOutputStream bous = new ByteArrayOutputStream()) {
      HttpResponse<InputStream> resposta = Unirest
          .get(String.format(dashboardStringFormat, dashboardId))
          .header("Accept",
              "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9")
          .header("Cookie", cookie).header("Accept-Encoding", "gzip, deflate").asBinary();

      if (resposta.getStatus() == HttpStatus.OK.value()) {
        Dashboard dashboard = new Dashboard();
        InputStream body = resposta.getBody();
        byte[] bytes = new byte[1024];
        int read = 0;
        while ((read = body.read(bytes)) > 0) {
          bous.write(bytes, 0, read);
        }
        dashboard.setContent(bous.toByteArray());
        dashboard.setId(dashboardId);
        cookie = resposta.getHeaders().getFirst(COOKIE_HEADER);
        ultimaChamada = new Date();
        return dashboard;
      }
    } catch (UnirestException e) {
      throw new AnalyticsException("Error requesting superset dashboards", e);
    } catch (IOException e) {
      throw new AnalyticsException("Error reading dashboard", e);
    }
    return null;
  }

  public String getCookie() {
    logIntoSuperset();
    return this.cookie;
  }

  String getCookieFromSuperset() {

    String[] tokenAndCookie = getCsrfTokenAndCookie();
    try {
      HttpResponse<String> response = Unirest.post(urlLogin)
          .header("Content-Type", "application/x-www-form-urlencoded")
          .header("cookie", tokenAndCookie[1]).field("username", "appuser")
          .field("password", "appuser").field("csrf_token", tokenAndCookie[0]).asString();
      return response.getHeaders().getFirst(COOKIE_HEADER);
    } catch (UnirestException e) {
      throw new AnalyticsException("Error requesting logging into superset", e);
    }
  }

  String[] getCsrfTokenAndCookie() {
    String[] ret = new String[2];
    String csrfToken = "";

    HttpHeaders headers = new HttpHeaders();
    headers.setContentType(MediaType.APPLICATION_JSON);
    headers.setAccept(Collections.singletonList(MediaType.APPLICATION_JSON));
    HttpEntity<?> request = new HttpEntity<>(headers);

    ResponseEntity<String> resposta = restTemplate
        .exchange(urlLogin, HttpMethod.GET, request, String.class, 1);

    if (resposta.getStatusCode() == HttpStatus.OK) {
      String respBody = resposta.getBody();
      int idx = 0;
      if ((idx = respBody.indexOf(CSRF_FIELD)) > 0) {
        csrfToken = respBody.substring(idx + CSRF_FIELD.length(),
            respBody.indexOf('\"', idx + CSRF_FIELD.length()));
      }
      ret[0] = csrfToken;
      ret[1] = resposta.getHeaders().get(COOKIE_HEADER).get(0);
    }
    return ret;
  }

  private List<Dashboard> getDashboardsListFromBody(String body) {
    List<Dashboard> dashboards = new ArrayList<>();
    int idxDashboard = body.indexOf(DASHBOARD_FIELD);
    int sharedLinkIndex = 1;
    while (idxDashboard >= 0) {
      String url = body.substring(idxDashboard + DASHBOARD_FIELD.length(),
          body.indexOf('"', idxDashboard + DASHBOARD_FIELD.length()));
      if (url.contains("dashboard")) {
        String dashboardName = body.substring(
            idxDashboard + DASHBOARD_FIELD.length() + url.length() + 2,
            body.indexOf('<', idxDashboard + DASHBOARD_FIELD.length()));
        dashboards.add(new Dashboard(dashboardName, url,
            urlSharedDashboard + sharedLinkIndex + "?standalone=true", sharedLinkIndex++));
      }
      idxDashboard = body.indexOf(DASHBOARD_FIELD,
          body.indexOf('<', idxDashboard + DASHBOARD_FIELD.length()));
    }

    return dashboards;
  }

  private void logIntoSuperset() {
    validaSupersetUrl();
    boolean timeoutttl = false;
    if (ultimaChamada != null) {
      Date dtAgora = new Date();
      long dtdiff = dtAgora.getTime() - ultimaChamada.getTime();
      long diffMinutes = dtdiff / (60 * 1000) % 60;
      if (diffMinutes > 10) {
        timeoutttl = true;
      }
    }
    if (StringUtils.isEmpty(this.cookie) || ultimaChamada == null || timeoutttl) {
      cookie = getCookieFromSuperset();
      ultimaChamada = new Date();
    }
  }

  private void validaSupersetUrl() {
    if (StringUtils.isBlank(this.urlRaiz) && StringUtils.isNotBlank(this.supersetHost)) {
      montaUrlsSuperset();
    } else if (StringUtils.isBlank(this.supersetHost)) {
      throw new RuntimeException("Configurações do Superset Server estão faltando");
    }
  }

  private void montaUrlsSuperset() {
    this.urlRaiz = "http://" + supersetHost + ":" + supersetPort + "/";
    this.urlGetDashboards = urlRaiz + "dashboard/list/";
    this.urlLogin = urlRaiz + "login/";
    this.urlSharedDashboard = urlRaiz + "r/";
  }

}
