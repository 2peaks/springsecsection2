package com.eazybytes.config;

import java.util.Collections;

import javax.servlet.http.HttpServletRequest;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;

import com.eazybytes.filter.AuthoritiesLoggingAfterFilter;
import com.eazybytes.filter.AuthoritiesLoggingAtFilter;
import com.eazybytes.filter.RequestValidationBeforeFilter;

@Configuration
public class ProjectSecurityConfig extends WebSecurityConfigurerAdapter {
	
	/*
	 *  /myAccount - Secured
	 *  /myBalance - Secured
	 *  /myLoans - Secured
	 *  /myCards - Secured
	 *  /notices - Not Secured
	 *  /contact - Not Secured
	 */
	@Override
	protected void configure(HttpSecurity http) throws Exception {
		
// 		SpringBood default from WebSecurityConfigurerAdapter.java 
//		http.authorizeRequests((requests) -> requests.anyRequest().authenticated());
//		http.formLogin();
//		http.httpBasic();
		
		http.cors().configurationSource(new CorsConfigurationSource() {
			@Override
			public CorsConfiguration getCorsConfiguration(HttpServletRequest request) {
				CorsConfiguration config = new CorsConfiguration();
				config.setAllowedOrigins(Collections.singletonList("http://localhost:4200"));
				config.setAllowedMethods(Collections.singletonList(("*")));
				config.setAllowCredentials(true);
				config.setAllowedHeaders(Collections.singletonList("*"));
				config.setMaxAge(3600L);
				return config;
			}			
		}).and()
		.csrf().ignoringAntMatchers("/contact").csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
		.and().addFilterBefore(new RequestValidationBeforeFilter(), BasicAuthenticationFilter.class)
		.addFilterAfter(new AuthoritiesLoggingAfterFilter(), BasicAuthenticationFilter.class)
		.addFilterAt(new AuthoritiesLoggingAtFilter(), BasicAuthenticationFilter.class) // don't use addFilterAt. No use.
		.authorizeRequests()
		.antMatchers("/myAccount").hasRole("USER") // for ROLE_USER in the authorities table
		.antMatchers("/myBalance").hasAnyRole("USER","ADMIN")
		.antMatchers("/myLoans").hasRole("ROOT")
		.antMatchers("/myCards").authenticated()
		.antMatchers("/user").authenticated()
		.antMatchers("/notices").permitAll()
		.antMatchers("/contact").permitAll();
		http.formLogin();
		http.httpBasic();	
	}
// ################################################################	
//	In memory authentication with user 'admin' and 'user'
//	@Override
//	protected void configure(AuthenticationManagerBuilder auth) throws Exception {
//		auth.inMemoryAuthentication().withUser("admin").password("12345").authorities("admin").and()
//		.withUser("user").password("12345").authorities("read").and()
//		.passwordEncoder(NoOpPasswordEncoder.getInstance());
//	}
// ################################################################
	
// ################################################################
////	In memory authentication another way. You have to pass a PasswordEncoder as a @Bean
//	@Override
//	protected void configure(AuthenticationManagerBuilder auth) throws Exception {
//		InMemoryUserDetailsManager userDetailsService = new InMemoryUserDetailsManager();
//		UserDetails user = User.withUsername("admin").password("12345").authorities("admin").build();
//		UserDetails user1 = User.withUsername("user").password("12345").authorities("read").build();
//		userDetailsService.createUser(user);
//		userDetailsService.createUser(user1);
//		auth.userDetailsService(userDetailsService);
//	}
//	
//	@Bean
//	public PasswordEncoder passwordEncoder() {
//		return NoOpPasswordEncoder.getInstance();
//	}
//// ################################################################

// ################################################################
//	Using MySql. The user 'happy' with password '12345' is manually created in the database.
	
	// The default UserDetailsService bean is no longer needed since EazyBankUserDetails.java is UserDetailsService.
//	@Bean
//	public UserDetailsService userDetailsService(DataSource dataSource) {
//		// the dataSource is created by Spring using the database info in application.properties
//		return new JdbcUserDetailsManager(dataSource);
//	}
	
	@Bean
	public PasswordEncoder passwordEncoder() {
		// You can get BCrypt value to enter into the database to update existing password in plain text
		// from https://bcrypt-generator.com/
		return new BCryptPasswordEncoder();
	}
// ################################################################

}
