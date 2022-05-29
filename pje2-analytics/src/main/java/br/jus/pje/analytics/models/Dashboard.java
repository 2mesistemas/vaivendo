package br.jus.pje.analytics.models;

public class Dashboard {
  private String name;
  private String url;
  private long id;
  private String sharedUrl;
  private byte[] content;

  public Dashboard() {
  }

  public Dashboard(String name, String url, String sharedUrl, long id) {
    this.name = name;
    this.url = url;
    this.sharedUrl = sharedUrl;
    this.id = id;
  }

  public String getName() {
    return name;
  }

  public void setName(String name) {
    this.name = name;
  }

  public String getUrl() {
    return url;
  }

  public void setUrl(String url) {
    this.url = url;
  }

  public String getSharedUrl() {
    return sharedUrl;
  }

  public void setSharedUrl(String sharedUrl) {
    this.sharedUrl = sharedUrl;
  }

  public long getId() {
    return id;
  }

  public void setId(long id) {
    this.id = id;
  }

  public byte[] getContent() {
    return content;
  }

  public void setContent(byte[] content) {
    this.content = content;
  }

  @Override
  public String toString() {
    return "{name: '" + name + "', url:'" + url + "', sharedUrl:'" + sharedUrl + "', id: " + id
        + " }";
  }
}
