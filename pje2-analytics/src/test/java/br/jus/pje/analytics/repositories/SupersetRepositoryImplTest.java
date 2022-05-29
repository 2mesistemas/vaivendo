package br.jus.pje.analytics.repositories;

import static org.hamcrest.CoreMatchers.equalTo;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.notNullValue;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.assertTrue;

import java.util.List;

import org.apache.commons.lang3.StringUtils;
import org.junit.Before;
import org.junit.Test;
import org.springframework.web.client.RestTemplate;

import br.jus.pje.analytics.models.Dashboard;

public class SupersetRepositoryImplTest {

  private SupersetRepositoryImpl unit;

  @Before
  public void setUp() throws Exception {
    RestTemplate restTemplate = new RestTemplate();
    unit = new SupersetRepositoryImpl(restTemplate);
  }

  @Test
  public void testGetCsrfToken() {
    String[] tokenAndCookie = unit.getCsrfTokenAndCookie();
    assertNotNull(tokenAndCookie);
    assertTrue(2 == tokenAndCookie.length);
    assertNotNull(tokenAndCookie[0]);
    assertNotNull(tokenAndCookie[1]);
  }

  @Test
  public void testGetCookie() {
    String cookie = unit.getCookieFromSuperset();
    assertTrue(StringUtils.isNotEmpty(cookie));
  }

  @Test
  public void testGetDashboards() {
    List<Dashboard> dashboards = unit.recuperaDashboards();
    assertTrue("Expected 5 got " + dashboards.size(), 6 == dashboards.size());
  }

  @Test
  public void testGetDashboard() {
    List<Dashboard> dashboards = unit.recuperaDashboards();
    assertTrue("Expected 6 got " + dashboards.size(), 6 == dashboards.size());

    Dashboard dashboard = dashboards.get(dashboards.size() - 1);
    Dashboard dashboardPorId = unit.recuperaDashboard(dashboard.getId());
    assertThat(dashboardPorId, is(notNullValue()));
    assertThat(dashboardPorId.getId(), is(equalTo(dashboard.getId())));
  }
}
