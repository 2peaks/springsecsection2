package com.eazybytes.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

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
		
		http.authorizeRequests()
		.antMatchers("/myAccount").authenticated()
		.antMatchers("/myBalance").authenticated()
		.antMatchers("/myLoans").authenticated()
		.antMatchers("/myCards").authenticated()
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
