<?php
/**
 * Tests de Event_Log.
 *
 * @package TotalSecurityExpert
 */

namespace TotalSecurityExpert\Tests\Unit;

use Mockery;
use TotalSecurityExpert\Event_Log;
use TotalSecurityExpert\Request;

/**
 * Escritura saneada que nunca lanza, purga y lectura con prepare().
 */
class EventLogTest extends TestCase {

	/**
	 * Event_Log con un Request que devuelve una IP fija.
	 *
	 * @return Event_Log
	 */
	private function make_log(): Event_Log {
		$request = Mockery::mock( Request::class );
		$request->shouldReceive( 'get_client_ip' )->andReturn( '203.0.113.7' );
		return new Event_Log( $request );
	}

	public function test_log_inserts_a_sanitized_row(): void {
		$wpdb = $this->mock_wpdb( 'wp_' );
		$row  = null;
		$wpdb->shouldReceive( 'insert' )->once()->andReturnUsing(
			function ( $table, $data ) use ( &$row ) {
				$row = array( $table, $data );
				return 1;
			}
		);

		$this->make_log()->log( 'Login-Limit', 'Blocked!', '<b>Bloqueado</b> user', array( 'attempts' => 5 ), 'warning' );

		$this->assertSame( 'wp_tsexp_events', $row[0] );
		$this->assertSame( 'login-limit', $row[1]['module'] );
		$this->assertSame( 'blocked', $row[1]['event'] );
		$this->assertSame( 'warning', $row[1]['severity'] );
		$this->assertSame( 'Bloqueado user', $row[1]['message'] );
		$this->assertSame( '203.0.113.7', $row[1]['ip'] );
		$this->assertSame( '{"attempts":5}', $row[1]['data'] );
		$this->assertMatchesRegularExpression( '/^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$/', $row[1]['created_at'] );
	}

	public function test_unknown_severity_falls_back_to_info_and_lengths_are_cut(): void {
		$wpdb = $this->mock_wpdb();
		$row  = null;
		$wpdb->shouldReceive( 'insert' )->once()->andReturnUsing(
			function ( $table, $data ) use ( &$row ) {
				$row = $data;
				return 1;
			}
		);

		$this->make_log()->log( str_repeat( 'a', 200 ), str_repeat( 'b', 200 ), str_repeat( 'c', 5000 ), array(), 'urgente' );

		$this->assertSame( 'info', $row['severity'] );
		$this->assertSame( 64, strlen( $row['module'] ) );
		$this->assertSame( 64, strlen( $row['event'] ) );
		$this->assertSame( 1000, strlen( $row['message'] ) );
	}

	public function test_secrets_are_never_stored(): void {
		$wpdb = $this->mock_wpdb();
		$row  = null;
		$wpdb->shouldReceive( 'insert' )->once()->andReturnUsing(
			function ( $table, $data ) use ( &$row ) {
				$row = $data;
				return 1;
			}
		);

		$this->make_log()->log(
			'm',
			'e',
			'msg',
			array(
				'username'   => 'admin',
				'password'   => 'hunter2',
				'user_pass'  => 'hunter2',
				'Cookie'     => 'wordpress_logged_in=abc',
				'_wpnonce'   => 'abc123',
				'auth_token' => 'tok',
				'nested'     => array(
					'secret_key' => 'zzz',
					'ok'         => 1,
				),
			)
		);

		$this->assertStringNotContainsString( 'hunter2', $row['data'] );
		$this->assertStringNotContainsString( 'abc123', $row['data'] );
		$this->assertStringNotContainsString( 'wordpress_logged_in', $row['data'] );
		$this->assertStringNotContainsString( 'zzz', $row['data'] );
		$this->assertStringContainsString( '"username":"admin"', $row['data'] );
		$this->assertStringContainsString( '"ok":1', $row['data'] );
	}

	public function test_extended_sensitive_keys_are_redacted_by_name_segment(): void {
		$redacted = array( 'key', 'api_key', 'apiKey', 'API-KEY', 'apikey', 'keys', 'auth', 'auth_header', 'session', 'session_id', 'otp', 'code', 'verification_code', 'hash', 'password_hash', 'salt', 'credential', 'credentials', 'Pass', 'pwd', 'cookie', '_wpnonce', 'token', 'secret', 'Authorization' );
		$data     = array();
		foreach ( $redacted as $key ) {
			$data[ $key ] = 'valor-secreto';
		}

		$stored = $this->log_and_decode( $data );

		foreach ( $redacted as $key ) {
			$this->assertSame( '[redacted]', $stored[ $key ], $key );
		}
		$this->assertStringNotContainsString( 'valor-secreto', wp_json_encode( $stored ) );
	}

	public function test_legitimate_keys_used_by_the_modules_are_not_redacted(): void {
		// Claves de data que usan hoy los modulos (grep en modules/*/) mas falsos positivos clasicos de una subcadena.
		$legit = array( 'user_login', 'login', 'username', 'user_id', 'ip', 'role', 'option', 'old', 'new', 'module', 'count', 'attempts', 'duration', 'until', 'lockouts', 'changed', 'source', 'plugin', 'new_role', 'old_roles', 'old_stylesheet', 'new_stylesheet', 'new_theme', 'network_wide', 'modules_enabled', 'modules_disabled', 'post_id', 'post_type', 'title', 'email', 'display_name', 'actor', 'action', 'status', 'type', 'url', 'fields', 'rows', 'monkey', 'author', 'footprint', 'encoded', 'hashtag', 'keyboard', 'authority' );
		$data  = array();
		foreach ( $legit as $key ) {
			$data[ $key ] = 'v-' . $key;
		}

		$stored = $this->log_and_decode( $data );

		foreach ( $legit as $key ) {
			$this->assertSame( 'v-' . $key, $stored[ $key ] ?? null, $key . ' no debe redactarse' );
		}
	}

	public function test_nested_sensitive_keys_are_redacted_too(): void {
		$stored = $this->log_and_decode(
			array(
				'request' => array(
					'headers' => array(
						'api_key' => 'zzz',
						'accept'  => 'json',
					),
				),
			)
		);

		$this->assertSame( '[redacted]', $stored['request']['headers']['api_key'] );
		$this->assertSame( 'json', $stored['request']['headers']['accept'] );
	}

	/**
	 * Registra un evento con estos datos y devuelve el JSON guardado ya decodificado.
	 *
	 * @param array<string,mixed> $data Datos.
	 * @return array<string,mixed>
	 */
	private function log_and_decode( array $data ): array {
		$wpdb = $this->mock_wpdb();
		$row  = null;
		$wpdb->shouldReceive( 'insert' )->once()->andReturnUsing(
			function ( $table, $values ) use ( &$row ) {
				$row = $values;
				return 1;
			}
		);

		$this->make_log()->log( 'm', 'e', 'msg', $data );

		return json_decode( $row['data'], true );
	}

	public function test_trim_deletes_the_oldest_rows_beyond_the_maximum_with_prepared_sql(): void {
		$wpdb    = $this->mock_wpdb();
		$queries = array();
		$wpdb->shouldReceive( 'get_var' )->once()->andReturnUsing(
			function ( $query ) use ( &$queries ) {
				$queries[] = $query;
				return '12345'; // Id de la fila numero 50 000 empezando por la mas nueva.
			}
		);
		$wpdb->shouldReceive( 'query' )->once()->andReturnUsing(
			function ( $query ) use ( &$queries ) {
				$queries[] = $query;
				return 7;
			}
		);

		$this->make_log()->trim_to_max_rows( 50000 );

		$this->assertSame( 'SELECT id FROM `wp_tsexp_events` ORDER BY id DESC LIMIT 1 OFFSET 49999', $queries[0] );
		$this->assertSame( 'DELETE FROM `wp_tsexp_events` WHERE id < 12345', $queries[1] );
	}

	public function test_trim_does_nothing_when_there_are_fewer_rows_than_the_maximum(): void {
		$wpdb = $this->mock_wpdb();
		$wpdb->shouldReceive( 'get_var' )->once()->andReturn( null );
		$wpdb->shouldNotReceive( 'query' );

		$this->make_log()->trim_to_max_rows( 50000 );

		$this->assertTrue( true );
	}

	public function test_trim_clamps_the_maximum_and_never_throws(): void {
		$wpdb    = $this->mock_wpdb();
		$queries = array();
		$wpdb->shouldReceive( 'get_var' )->twice()->andReturnUsing(
			function ( $query ) use ( &$queries ) {
				$queries[] = $query;
				return null;
			}
		);

		$this->make_log()->trim_to_max_rows( 5 );
		$this->make_log()->trim_to_max_rows( 99999999 );

		$this->assertStringEndsWith( 'OFFSET 999', $queries[0] );
		$this->assertStringEndsWith( 'OFFSET 999999', $queries[1] );

		$wpdb->shouldReceive( 'get_var' )->andThrow( new \RuntimeException( 'BD caida' ) );
		$this->make_log()->trim_to_max_rows( 50000 );
	}

	public function test_log_never_throws_when_the_database_fails(): void {
		$wpdb = $this->mock_wpdb();
		$wpdb->shouldReceive( 'insert' )->once()->andThrow( new \RuntimeException( 'BD caida' ) );

		$this->make_log()->log( 'm', 'e', 'msg' );

		$this->assertTrue( true ); // No ha lanzado.
	}

	public function test_log_without_wpdb_does_nothing(): void {
		unset( $GLOBALS['wpdb'] );

		$this->make_log()->log( 'm', 'e', 'msg' );

		$this->assertTrue( true );
	}

	public function test_purge_deletes_old_rows_with_prepared_sql(): void {
		$wpdb = $this->mock_wpdb();
		$sql  = '';
		$wpdb->shouldReceive( 'query' )->once()->andReturnUsing(
			function ( $query ) use ( &$sql ) {
				$sql = $query;
				return 3;
			}
		);

		$this->make_log()->purge( 30 );

		$this->assertMatchesRegularExpression( "/^DELETE FROM `wp_tsexp_events` WHERE created_at < '\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}'$/", $sql );
	}

	public function test_get_events_filters_with_a_whitelist_and_uses_prepare(): void {
		$wpdb    = $this->mock_wpdb();
		$queries = array();
		$wpdb->shouldReceive( 'get_var' )->once()->andReturnUsing(
			function ( $query ) use ( &$queries ) {
				$queries[] = $query;
				return '120';
			}
		);
		$wpdb->shouldReceive( 'get_results' )->once()->andReturnUsing(
			function ( $query ) use ( &$queries ) {
				$queries[] = $query;
				return array( array( 'id' => '1' ) );
			}
		);

		$result = $this->make_log()->get_events(
			array(
				'module'   => "login-limit'; DROP TABLE x;--",
				'severity' => 'warning',
				'page'     => 3,
				'per_page' => 50,
			)
		);

		$this->assertSame( 120, $result['total'] );
		$this->assertSame( array( array( 'id' => '1' ) ), $result['items'] );
		// El modulo se sanea con sanitize_key (queda sin comillas ni punto y coma) y va como valor entre comillas.
		$this->assertSame( "SELECT COUNT(*) FROM `wp_tsexp_events` WHERE module = 'login-limitdroptablex--' AND severity = 'warning'", $queries[0] );
		$this->assertStringEndsWith( 'ORDER BY id DESC LIMIT 50 OFFSET 100', $queries[1] );
	}

	public function test_get_events_ignores_an_unknown_severity(): void {
		$wpdb    = $this->mock_wpdb();
		$queries = array();
		$wpdb->shouldReceive( 'get_var' )->once()->andReturnUsing(
			function ( $query ) use ( &$queries ) {
				$queries[] = $query;
				return '0';
			}
		);
		$wpdb->shouldReceive( 'get_results' )->once()->andReturn( null );

		$result = $this->make_log()->get_events(
			array(
				'severity' => 'x OR 1=1',
				'per_page' => 99999,
				'page'     => -4,
			)
		);

		$this->assertSame( 'SELECT COUNT(*) FROM `wp_tsexp_events`', $queries[0] );
		$this->assertSame( array(), $result['items'] );
		$this->assertSame( 0, $result['total'] );
	}

	public function test_get_events_returns_empty_when_the_database_fails(): void {
		$wpdb = $this->mock_wpdb();
		$wpdb->shouldReceive( 'get_var' )->andThrow( new \RuntimeException( 'BD caida' ) );

		$this->assertSame(
			array(
				'items' => array(),
				'total' => 0,
			),
			$this->make_log()->get_events()
		);
	}
}
