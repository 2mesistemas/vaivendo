package br.jus.pje.analytics.secutiry;

import java.util.Arrays;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.web.servlet.config.annotation.CorsRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

@Configuration
public class RestSecurityConfig extends WebSecurityConfigurerAdapter {
	private static final Logger log = LoggerFactory.getLogger(RestSecurityConfig.class);
	private static final String variableName = "user.token";
	@Override
	protected void configure(AuthenticationManagerBuilder auth) throws Exception {
		log.debug ("configure(AuthenticationManagerBuilder auth)");
		
		String token = System.getenv(variableName);
		if(token == null || token.isEmpty())
			token = System.getProperty(variableName);
		if ( token==null || token.isEmpty() ) {
			super.configure(auth);
		}
		else
		{
			log.debug ("TOKEN=" + token );
			auth.inMemoryAuthentication()
				.passwordEncoder(org.springframework.security.crypto.password.NoOpPasswordEncoder.getInstance())
				.withUser("user").password(token)
				.roles("USER");
		}
	}

	@Override
	public void configure(WebSecurity web) throws Exception {
		log.debug ("configure(WebSecurity web)");
		super.configure(web);
	}

	@Override
	protected void configure(HttpSecurity http) throws Exception {
		log.debug ("configure(configure http)");
		http
			.httpBasic()
			.and()
			.authorizeRequests()
			.antMatchers("/**")
			.hasRole("USER")
			.and()
			.cors()
			.and()
			.csrf()
			.disable()
			.headers()
			.frameOptions()
			.disable();	
	}

    @Bean
    public WebMvcConfigurer corsConfigurer() {
        return new WebMvcConfigurer() {
            @Override
            public void addCorsMappings(CorsRegistry registry) {
               			    // This wildcard pattern matches any host from domain.com and url patterns like "https:microservice.division.domain.com/version1/some_endpoint"
                registry.addMapping("/**").allowedMethods("*").allowedOriginPatterns("https://*.jus.br").allowCredentials(true);
            }
        };
    }	

}
