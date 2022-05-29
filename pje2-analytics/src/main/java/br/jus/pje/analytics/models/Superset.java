package br.jus.pje.analytics.models;

import java.util.ArrayList;
import java.util.List;

public class Superset {
  private String cookie;
  private List<Dashboard> dashboards;

  public Superset(String cookie, List<Dashboard> dashboards) {
    this.cookie = cookie;
    this.dashboards = dashboards;
  }

  public Superset(String cookie, Dashboard dashboard) {
    this.dashboards = new ArrayList<>();
    this.dashboards.add(dashboard);
    this.cookie = cookie;
  }

  public String getCookie() {
    return cookie;
  }

  public List<Dashboard> getDashboards() {
    return dashboards;
  }
}
