package com.snhu.sslserver;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

import org.apache.catalina.filters.RateLimitFilter;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;

@SpringBootApplication
public class SslServerApplication {

	public static void main(String[] args) {
	    try {
	        SpringApplication.run(SslServerApplication.class, args);
	    }
	    // Catch-all for start-up failures, aborts application
	    // TODO: Implement sepcific runtime exception handling when appropriate to promote crash recovery
	    catch (Exception e) {
	        System.err.println("Fatal startup error: " + e.getMessage());
	        System.exit(1);
	    }
	}
	
	@Bean
	// Rate limit filter to restrict consecutive requests
	public FilterRegistrationBean<RateLimitFilter> tomcatRateLimitFilter() {
		
	    FilterRegistrationBean<RateLimitFilter> bean =
	            new FilterRegistrationBean<>();

	    RateLimitFilter filter = new RateLimitFilter();

	    bean.setFilter(filter);
	    // Protect /handshake endpoint, no other valid endpoints in application
	    bean.addUrlPatterns("/handshake"); // Protect endpoint

	    // Only allow 1 request per second in a 10 second window
	    bean.addInitParameter("bucketRequests", "10");
	    bean.addInitParameter("bucketDuration", "10");
	    bean.addInitParameter("enforce", "true");

	    return bean;
	}
	
	@Bean
	// Only allow access to /handshake enpoint only
	public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
	    http.authorizeHttpRequests(
	    		authz -> authz.antMatchers("/handshake").permitAll().anyRequest().authenticated()
	    		)
	    .requiresChannel(channel -> channel.anyRequest().requiresSecure()
	        );
	    return http.build();
	}   
}
