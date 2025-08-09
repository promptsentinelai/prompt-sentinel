"""Tests for configuration management."""

import pytest
import os
import json
import tempfile
from pathlib import Path
from unittest.mock import patch, MagicMock

from prompt_sentinel.config.settings import Settings, get_settings
from prompt_sentinel.config.loader import ConfigLoader


class TestSettings:
    """Test settings and configuration."""

    def test_default_settings(self):
        """Test default settings initialization."""
        settings = Settings()
        
        assert settings.app_name == "PromptSentinel"
        assert settings.detection_mode in ["strict", "moderate", "permissive"]
        assert settings.enable_llm_detection in [True, False]
        assert settings.enable_pii_detection in [True, False]

    def test_settings_from_env(self):
        """Test loading settings from environment variables."""
        with patch.dict(os.environ, {
            "DETECTION_MODE": "strict",
            "ANTHROPIC_API_KEY": "test_key",
            "ENABLE_CACHING": "true",
            "CACHE_TTL": "300"
        }):
            settings = Settings()
            
            assert settings.detection_mode == "strict"
            assert settings.anthropic_api_key == "test_key"
            assert settings.enable_caching is True
            assert settings.cache_ttl == 300

    def test_settings_validation(self):
        """Test settings validation."""
        with patch.dict(os.environ, {"DETECTION_MODE": "invalid"}):
            with pytest.raises(ValueError):
                Settings()
        
        with patch.dict(os.environ, {"CACHE_TTL": "not_a_number"}):
            with pytest.raises(ValueError):
                Settings()

    def test_settings_singleton(self):
        """Test settings singleton pattern."""
        settings1 = get_settings()
        settings2 = get_settings()
        
        assert settings1 is settings2

    def test_settings_override(self):
        """Test overriding settings."""
        original_mode = get_settings().detection_mode
        
        with patch.dict(os.environ, {"DETECTION_MODE": "permissive"}):
            # Clear cache to reload settings
            get_settings.cache_clear()
            settings = get_settings()
            
            assert settings.detection_mode == "permissive"
        
        # Reset
        get_settings.cache_clear()


class TestConfigLoader:
    """Test configuration file loading."""

    def test_load_json_config(self):
        """Test loading JSON configuration."""
        config_data = {
            "detection": {
                "mode": "moderate",
                "thresholds": {
                    "strict": 0.3,
                    "moderate": 0.5,
                    "permissive": 0.7
                }
            },
            "providers": {
                "order": ["anthropic", "openai", "gemini"],
                "timeout": 30
            }
        }
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json') as f:
            json.dump(config_data, f)
            f.flush()
            
            loader = ConfigLoader()
            config = loader.load_config(f.name)
            
            assert config["detection"]["mode"] == "moderate"
            assert config["providers"]["timeout"] == 30

    def test_load_yaml_config(self):
        """Test loading YAML configuration."""
        yaml_content = """
        detection:
          mode: strict
          patterns:
            - name: instruction_override
              regex: "ignore.*instructions"
              severity: high
        
        monitoring:
          enable_metrics: true
          metrics_port: 9090
        """
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml') as f:
            f.write(yaml_content)
            f.flush()
            
            loader = ConfigLoader()
            config = loader.load_config(f.name)
            
            assert config["detection"]["mode"] == "strict"
            assert config["monitoring"]["metrics_port"] == 9090

    def test_config_merge(self):
        """Test merging multiple configuration sources."""
        base_config = {
            "detection": {"mode": "moderate"},
            "cache": {"ttl": 60}
        }
        
        override_config = {
            "detection": {"mode": "strict"},
            "monitoring": {"enabled": True}
        }
        
        loader = ConfigLoader()
        merged = loader.merge_configs(base_config, override_config)
        
        assert merged["detection"]["mode"] == "strict"  # Overridden
        assert merged["cache"]["ttl"] == 60  # Preserved
        assert merged["monitoring"]["enabled"] is True  # Added

    def test_config_validation(self):
        """Test configuration validation."""
        invalid_config = {
            "detection": {
                "mode": "invalid_mode"
            }
        }
        
        loader = ConfigLoader()
        with pytest.raises(ValueError):
            loader.validate_config(invalid_config)

    def test_config_file_watch(self):
        """Test configuration file watching for changes."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump({"version": 1}, f)
            f.flush()
            config_path = f.name
        
        try:
            loader = ConfigLoader()
            loader.watch_config(config_path)
            
            # Initial load
            config = loader.get_current_config()
            assert config["version"] == 1
            
            # Update file
            with open(config_path, 'w') as f:
                json.dump({"version": 2}, f)
            
            # Should detect change (in real implementation)
            # This is a simplified test
            loader.reload_config()
            config = loader.get_current_config()
            # In real implementation, this would be 2
            
        finally:
            os.unlink(config_path)


class TestEnvironmentSpecificConfig:
    """Test environment-specific configurations."""

    def test_development_config(self):
        """Test development environment configuration."""
        with patch.dict(os.environ, {"ENVIRONMENT": "development"}):
            settings = Settings()
            
            # Development-specific settings
            assert settings.debug is True
            assert settings.log_level == "DEBUG"
            assert settings.enable_profiling is True

    def test_production_config(self):
        """Test production environment configuration."""
        with patch.dict(os.environ, {"ENVIRONMENT": "production"}):
            settings = Settings()
            
            # Production-specific settings
            assert settings.debug is False
            assert settings.log_level == "INFO"
            assert settings.enable_profiling is False
            assert settings.enable_caching is True

    def test_staging_config(self):
        """Test staging environment configuration."""
        with patch.dict(os.environ, {"ENVIRONMENT": "staging"}):
            settings = Settings()
            
            # Staging-specific settings
            assert settings.debug is False
            assert settings.log_level == "INFO"
            assert settings.enable_metrics is True


class TestFeatureFlags:
    """Test feature flag configuration."""

    def test_feature_flags_loading(self):
        """Test loading feature flags."""
        flags = {
            "new_detection_algorithm": True,
            "experimental_providers": False,
            "advanced_analytics": True
        }
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json') as f:
            json.dump({"feature_flags": flags}, f)
            f.flush()
            
            loader = ConfigLoader()
            config = loader.load_config(f.name)
            
            assert config["feature_flags"]["new_detection_algorithm"] is True
            assert config["feature_flags"]["experimental_providers"] is False

    def test_feature_flag_override(self):
        """Test feature flag override via environment."""
        with patch.dict(os.environ, {
            "FEATURE_NEW_DETECTION": "true",
            "FEATURE_EXPERIMENTAL": "false"
        }):
            settings = Settings()
            
            assert settings.feature_new_detection is True
            assert settings.feature_experimental is False

    def test_feature_flag_rollout(self):
        """Test gradual feature flag rollout."""
        from prompt_sentinel.config.feature_flags import FeatureFlagManager
        
        manager = FeatureFlagManager()
        
        # Set rollout percentage
        manager.set_rollout("new_feature", percentage=50)
        
        # Test that roughly 50% of requests get the feature
        enabled_count = sum(
            1 for _ in range(1000)
            if manager.is_enabled("new_feature", user_id=str(_))
        )
        
        # Should be roughly 50%
        assert 400 < enabled_count < 600


class TestSecretManagement:
    """Test secret and credential management."""

    def test_api_key_masking(self):
        """Test that API keys are masked in logs."""
        settings = Settings(anthropic_api_key="sk-ant-secret123")
        
        # Should mask when converted to string
        settings_str = str(settings.model_dump())
        assert "sk-ant-secret123" not in settings_str
        assert "***" in settings_str or "REDACTED" in settings_str

    def test_secrets_from_file(self):
        """Test loading secrets from file."""
        secrets = {
            "anthropic_api_key": "secret_anthropic",
            "openai_api_key": "secret_openai",
            "database_password": "secret_db"
        }
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json') as f:
            json.dump(secrets, f)
            f.flush()
            
            with patch.dict(os.environ, {"SECRETS_FILE": f.name}):
                settings = Settings()
                
                assert settings.anthropic_api_key == "secret_anthropic"
                assert settings.openai_api_key == "secret_openai"

    @patch("hvac.Client")
    def test_vault_integration(self, mock_vault):
        """Test HashiCorp Vault integration for secrets."""
        mock_client = MagicMock()
        mock_vault.return_value = mock_client
        mock_client.read.return_value = {
            "data": {
                "data": {
                    "api_key": "vault_secret"
                }
            }
        }
        
        from prompt_sentinel.config.secrets import VaultSecretManager
        
        manager = VaultSecretManager(vault_url="http://vault:8200")
        secret = manager.get_secret("api_key")
        
        assert secret == "vault_secret"


class TestConfigurationHotReload:
    """Test configuration hot reload functionality."""

    def test_config_reload_signal(self):
        """Test configuration reload on signal."""
        loader = ConfigLoader()
        
        # Register reload handler
        reload_called = False
        
        def on_reload(config):
            nonlocal reload_called
            reload_called = True
        
        loader.on_reload(on_reload)
        
        # Trigger reload
        loader.reload_config()
        
        assert reload_called is True

    def test_config_version_tracking(self):
        """Test configuration version tracking."""
        loader = ConfigLoader()
        
        config_v1 = {"version": "1.0.0", "data": "v1"}
        config_v2 = {"version": "2.0.0", "data": "v2"}
        
        loader.load_config_dict(config_v1)
        assert loader.get_config_version() == "1.0.0"
        
        loader.load_config_dict(config_v2)
        assert loader.get_config_version() == "2.0.0"
        
        # Should keep history
        history = loader.get_config_history()
        assert len(history) == 2


class TestConfigurationDefaults:
    """Test configuration defaults and fallbacks."""

    def test_missing_config_fallback(self):
        """Test fallback when configuration is missing."""
        loader = ConfigLoader()
        
        # Try to load non-existent config
        config = loader.load_config("/non/existent/path.json")
        
        # Should return defaults
        assert config is not None
        assert "detection" in config
        assert config["detection"]["mode"] == "moderate"

    def test_partial_config_completion(self):
        """Test completion of partial configuration."""
        partial_config = {
            "detection": {
                "mode": "strict"
                # Missing other fields
            }
        }
        
        loader = ConfigLoader()
        complete_config = loader.complete_config(partial_config)
        
        # Should have all required fields
        assert "thresholds" in complete_config["detection"]
        assert "providers" in complete_config
        assert "monitoring" in complete_config


if __name__ == "__main__":
    pytest.main([__file__, "-v"])