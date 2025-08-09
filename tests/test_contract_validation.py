"""Contract and schema validation tests for PromptSentinel."""

import pytest
import json
import jsonschema
from typing import Dict, Any, List
from pydantic import ValidationError
from datetime import datetime

from prompt_sentinel.models.schemas import (
    Message, Role, Verdict, DetectionResponse,
    AnalysisResponse, SimplePromptRequest, 
    StructuredPromptRequest, UnifiedDetectionRequest
)


class TestAPIContractValidation:
    """Test API contract validation."""

    @pytest.fixture
    def v1_detect_schema(self):
        """OpenAPI schema for v1 detect endpoint."""
        return {
            "type": "object",
            "required": ["prompt"],
            "properties": {
                "prompt": {"type": "string", "minLength": 1, "maxLength": 100000}
            }
        }

    @pytest.fixture
    def v2_detect_schema(self):
        """OpenAPI schema for v2 detect endpoint."""
        return {
            "type": "object",
            "required": ["input"],
            "properties": {
                "input": {
                    "type": "object",
                    "required": ["messages"],
                    "properties": {
                        "messages": {
                            "type": "array",
                            "items": {
                                "type": "object",
                                "required": ["role", "content"],
                                "properties": {
                                    "role": {"enum": ["system", "user", "assistant"]},
                                    "content": {"type": "string"}
                                }
                            }
                        }
                    }
                },
                "config": {
                    "type": "object",
                    "properties": {
                        "mode": {"enum": ["strict", "moderate", "permissive"]},
                        "check_pii": {"type": "boolean"},
                        "include_metadata": {"type": "boolean"}
                    }
                }
            }
        }

    def test_v1_valid_request(self, v1_detect_schema):
        """Test valid v1 request validation."""
        valid_requests = [
            {"prompt": "What is the weather today?"},
            {"prompt": "a" * 1000},  # Long prompt
            {"prompt": "Special chars: !@#$%^&*()"},
        ]
        
        for request in valid_requests:
            jsonschema.validate(request, v1_detect_schema)

    def test_v1_invalid_request(self, v1_detect_schema):
        """Test invalid v1 request validation."""
        invalid_requests = [
            {},  # Missing prompt
            {"prompt": ""},  # Empty prompt
            {"prompt": 123},  # Wrong type
            {"text": "wrong field"},  # Wrong field name
        ]
        
        for request in invalid_requests:
            with pytest.raises(jsonschema.ValidationError):
                jsonschema.validate(request, v1_detect_schema)

    def test_v2_valid_request(self, v2_detect_schema):
        """Test valid v2 request validation."""
        valid_requests = [
            {
                "input": {
                    "messages": [
                        {"role": "user", "content": "Hello"}
                    ]
                }
            },
            {
                "input": {
                    "messages": [
                        {"role": "system", "content": "You are helpful"},
                        {"role": "user", "content": "Test"}
                    ]
                },
                "config": {
                    "mode": "strict",
                    "check_pii": True
                }
            }
        ]
        
        for request in valid_requests:
            jsonschema.validate(request, v2_detect_schema)

    def test_v2_invalid_request(self, v2_detect_schema):
        """Test invalid v2 request validation."""
        invalid_requests = [
            {"messages": []},  # Missing input wrapper
            {
                "input": {
                    "messages": [
                        {"role": "invalid", "content": "Test"}  # Invalid role
                    ]
                }
            },
            {
                "input": {
                    "messages": [
                        {"content": "Missing role"}  # Missing role
                    ]
                }
            }
        ]
        
        for request in invalid_requests:
            with pytest.raises(jsonschema.ValidationError):
                jsonschema.validate(request, v2_detect_schema)


class TestResponseContractValidation:
    """Test response contract validation."""

    @pytest.fixture
    def detection_response_schema(self):
        """Schema for detection response."""
        return {
            "type": "object",
            "required": ["verdict", "confidence", "reasons"],
            "properties": {
                "verdict": {"enum": ["ALLOW", "FLAG", "STRIP", "BLOCK"]},
                "confidence": {"type": "number", "minimum": 0, "maximum": 1},
                "reasons": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "required": ["category", "description"],
                        "properties": {
                            "category": {"type": "string"},
                            "description": {"type": "string"},
                            "confidence": {"type": "number"},
                            "source": {"type": "string"}
                        }
                    }
                },
                "processing_time_ms": {"type": "number"},
                "request_id": {"type": "string"}
            }
        }

    def test_valid_detection_response(self, detection_response_schema):
        """Test valid detection response."""
        response = {
            "verdict": "BLOCK",
            "confidence": 0.95,
            "reasons": [
                {
                    "category": "INSTRUCTION_OVERRIDE",
                    "description": "Attempt to override instructions",
                    "confidence": 0.9,
                    "source": "heuristic"
                }
            ],
            "processing_time_ms": 45.2,
            "request_id": "req_123"
        }
        
        jsonschema.validate(response, detection_response_schema)

    def test_invalid_detection_response(self, detection_response_schema):
        """Test invalid detection response."""
        invalid_responses = [
            {
                "verdict": "INVALID",  # Invalid verdict
                "confidence": 0.5,
                "reasons": []
            },
            {
                "verdict": "ALLOW",
                "confidence": 1.5,  # Out of range
                "reasons": []
            },
            {
                "verdict": "ALLOW",
                # Missing confidence
                "reasons": []
            }
        ]
        
        for response in invalid_responses:
            with pytest.raises(jsonschema.ValidationError):
                jsonschema.validate(response, detection_response_schema)


class TestPydanticSchemaValidation:
    """Test Pydantic model validation."""

    def test_message_validation(self):
        """Test Message model validation."""
        # Valid messages
        valid_messages = [
            Message(role=Role.USER, content="Hello"),
            Message(role=Role.SYSTEM, content="You are helpful"),
            Message(role=Role.ASSISTANT, content="I can help")
        ]
        
        for msg in valid_messages:
            assert msg.role in Role
            assert isinstance(msg.content, str)
        
        # Invalid messages
        with pytest.raises(ValidationError):
            Message(role="invalid", content="Test")
        
        with pytest.raises(ValidationError):
            Message(role=Role.USER, content=123)  # Wrong type
        
        with pytest.raises(ValidationError):
            Message(role=Role.USER)  # Missing content

    def test_detection_response_validation(self):
        """Test DetectionResponse model validation."""
        # Valid response
        response = DetectionResponse(
            verdict=Verdict.ALLOW,
            confidence=0.95,
            reasons=[],
            processing_time_ms=10.5,
            request_id="test_123"
        )
        
        assert response.verdict == Verdict.ALLOW
        assert 0 <= response.confidence <= 1
        
        # Invalid confidence
        with pytest.raises(ValidationError):
            DetectionResponse(
                verdict=Verdict.ALLOW,
                confidence=1.5,  # Out of range
                reasons=[]
            )

    def test_request_model_validation(self):
        """Test request model validation."""
        # Simple prompt request
        simple = SimplePromptRequest(prompt="Test prompt")
        assert simple.prompt == "Test prompt"
        
        # Structured prompt request
        structured = StructuredPromptRequest(
            messages=[
                Message(role=Role.USER, content="Test")
            ]
        )
        assert len(structured.messages) == 1
        
        # Unified detection request
        unified = UnifiedDetectionRequest(
            input=structured,
            config={
                "mode": "strict",
                "check_pii": True
            }
        )
        assert unified.config["mode"] == "strict"

    def test_optional_field_validation(self):
        """Test optional field validation."""
        # With optional fields
        response = DetectionResponse(
            verdict=Verdict.ALLOW,
            confidence=0.8,
            reasons=[],
            metadata={"extra": "data"},
            tags=["test", "validation"]
        )
        
        assert response.metadata == {"extra": "data"}
        assert "test" in response.tags
        
        # Without optional fields
        minimal = DetectionResponse(
            verdict=Verdict.ALLOW,
            confidence=0.8,
            reasons=[]
        )
        
        assert minimal.metadata is None or minimal.metadata == {}


class TestBackwardCompatibility:
    """Test backward compatibility of API contracts."""

    def test_v1_to_v2_migration(self):
        """Test migration from v1 to v2 format."""
        # V1 format
        v1_request = {"prompt": "Test prompt"}
        
        # Convert to v2 format
        v2_request = {
            "input": {
                "messages": [
                    {"role": "user", "content": v1_request["prompt"]}
                ]
            }
        }
        
        # Validate v2 format
        structured = StructuredPromptRequest(
            messages=[Message(**msg) for msg in v2_request["input"]["messages"]]
        )
        assert structured.messages[0].content == "Test prompt"

    def test_response_format_compatibility(self):
        """Test response format compatibility."""
        # V1 response format
        v1_response = {
            "is_malicious": True,
            "confidence": 0.9,
            "reasons": ["Detected threat"]
        }
        
        # V2 response format
        v2_response = {
            "verdict": "BLOCK",
            "confidence": 0.9,
            "reasons": [
                {
                    "category": "THREAT",
                    "description": "Detected threat"
                }
            ]
        }
        
        # Both should convey same information
        assert v1_response["is_malicious"] == (v2_response["verdict"] == "BLOCK")
        assert v1_response["confidence"] == v2_response["confidence"]


class TestDataTypeValidation:
    """Test data type validation and coercion."""

    def test_string_length_validation(self):
        """Test string length constraints."""
        from pydantic import BaseModel, Field
        
        class StringModel(BaseModel):
            short: str = Field(min_length=1, max_length=10)
            medium: str = Field(min_length=5, max_length=100)
            long: str = Field(min_length=10, max_length=10000)
        
        # Valid
        model = StringModel(
            short="test",
            medium="medium text",
            long="a" * 100
        )
        
        # Too short
        with pytest.raises(ValidationError):
            StringModel(short="", medium="test", long="short")
        
        # Too long
        with pytest.raises(ValidationError):
            StringModel(short="a" * 11, medium="test" * 50, long="ok" * 10)

    def test_numeric_range_validation(self):
        """Test numeric range constraints."""
        from pydantic import BaseModel, Field
        
        class NumericModel(BaseModel):
            percentage: float = Field(ge=0, le=1)
            count: int = Field(ge=0)
            temperature: float = Field(ge=-273.15)  # Absolute zero
        
        # Valid
        model = NumericModel(
            percentage=0.5,
            count=10,
            temperature=20.0
        )
        
        # Out of range
        with pytest.raises(ValidationError):
            NumericModel(percentage=1.5, count=-1, temperature=-300)

    def test_enum_validation(self):
        """Test enum validation."""
        from enum import Enum
        from pydantic import BaseModel
        
        class Status(str, Enum):
            ACTIVE = "active"
            INACTIVE = "inactive"
            PENDING = "pending"
        
        class StatusModel(BaseModel):
            status: Status
        
        # Valid
        model = StatusModel(status="active")
        assert model.status == Status.ACTIVE
        
        # Invalid
        with pytest.raises(ValidationError):
            StatusModel(status="invalid")

    def test_datetime_validation(self):
        """Test datetime validation and parsing."""
        from pydantic import BaseModel
        from datetime import datetime
        
        class TimeModel(BaseModel):
            created_at: datetime
            updated_at: datetime = None
        
        # Various datetime formats
        model = TimeModel(
            created_at="2024-01-01T12:00:00Z",
            updated_at="2024-01-01 13:00:00"
        )
        
        assert isinstance(model.created_at, datetime)
        assert model.created_at.year == 2024
        
        # Invalid datetime
        with pytest.raises(ValidationError):
            TimeModel(created_at="not a datetime")


class TestNestedValidation:
    """Test nested object validation."""

    def test_deeply_nested_validation(self):
        """Test validation of deeply nested structures."""
        from pydantic import BaseModel
        from typing import List, Optional
        
        class Address(BaseModel):
            street: str
            city: str
            country: str
        
        class Contact(BaseModel):
            email: str
            phone: Optional[str] = None
            address: Optional[Address] = None
        
        class User(BaseModel):
            name: str
            contacts: List[Contact]
        
        # Valid nested structure
        user = User(
            name="John Doe",
            contacts=[
                Contact(
                    email="john@example.com",
                    address=Address(
                        street="123 Main St",
                        city="Springfield",
                        country="USA"
                    )
                ),
                Contact(email="john.doe@work.com")
            ]
        )
        
        assert len(user.contacts) == 2
        assert user.contacts[0].address.city == "Springfield"
        
        # Invalid nested field
        with pytest.raises(ValidationError) as exc:
            User(
                name="Jane",
                contacts=[
                    Contact(
                        email="invalid-email",  # Invalid email format
                        address=Address(
                            street="",  # Empty required field
                            city="City",
                            country="Country"
                        )
                    )
                ]
            )

    def test_recursive_validation(self):
        """Test recursive structure validation."""
        from pydantic import BaseModel
        from typing import List, Optional
        
        class TreeNode(BaseModel):
            value: str
            children: Optional[List['TreeNode']] = []
        
        # Update forward references
        TreeNode.model_rebuild()
        
        # Create recursive structure
        tree = TreeNode(
            value="root",
            children=[
                TreeNode(value="child1"),
                TreeNode(
                    value="child2",
                    children=[
                        TreeNode(value="grandchild")
                    ]
                )
            ]
        )
        
        assert tree.value == "root"
        assert len(tree.children) == 2
        assert tree.children[1].children[0].value == "grandchild"


class TestCustomValidation:
    """Test custom validation rules."""

    def test_custom_validators(self):
        """Test custom field validators."""
        from pydantic import BaseModel, validator
        
        class CustomModel(BaseModel):
            email: str
            password: str
            age: int
            
            @validator('email')
            def validate_email(cls, v):
                if '@' not in v:
                    raise ValueError('Invalid email')
                return v.lower()
            
            @validator('password')
            def validate_password(cls, v):
                if len(v) < 8:
                    raise ValueError('Password too short')
                if not any(c.isdigit() for c in v):
                    raise ValueError('Password must contain a number')
                return v
            
            @validator('age')
            def validate_age(cls, v):
                if v < 0 or v > 150:
                    raise ValueError('Invalid age')
                return v
        
        # Valid
        model = CustomModel(
            email="USER@EXAMPLE.COM",
            password="password123",
            age=30
        )
        assert model.email == "user@example.com"  # Normalized
        
        # Invalid
        with pytest.raises(ValidationError):
            CustomModel(
                email="invalid",
                password="short",
                age=200
            )

    def test_cross_field_validation(self):
        """Test validation across multiple fields."""
        from pydantic import BaseModel, root_validator
        
        class DateRange(BaseModel):
            start_date: datetime
            end_date: datetime
            
            @root_validator
            def validate_dates(cls, values):
                start = values.get('start_date')
                end = values.get('end_date')
                if start and end and start >= end:
                    raise ValueError('Start date must be before end date')
                return values
        
        # Valid
        valid_range = DateRange(
            start_date="2024-01-01T00:00:00Z",
            end_date="2024-12-31T23:59:59Z"
        )
        
        # Invalid
        with pytest.raises(ValidationError):
            DateRange(
                start_date="2024-12-31T00:00:00Z",
                end_date="2024-01-01T00:00:00Z"
            )


class TestSerializationValidation:
    """Test serialization and deserialization validation."""

    def test_json_serialization(self):
        """Test JSON serialization of models."""
        response = DetectionResponse(
            verdict=Verdict.BLOCK,
            confidence=0.95,
            reasons=[],
            processing_time_ms=10.5
        )
        
        # Serialize to JSON
        json_str = response.model_dump_json()
        data = json.loads(json_str)
        
        assert data["verdict"] == "BLOCK"
        assert data["confidence"] == 0.95
        
        # Deserialize from JSON
        restored = DetectionResponse.model_validate_json(json_str)
        assert restored.verdict == Verdict.BLOCK

    def test_dict_serialization(self):
        """Test dict serialization with options."""
        message = Message(role=Role.USER, content="Test")
        
        # Include all fields
        full_dict = message.model_dump()
        assert "role" in full_dict
        assert "content" in full_dict
        
        # Exclude defaults
        minimal_dict = message.model_dump(exclude_defaults=True)
        assert len(minimal_dict) <= len(full_dict)
        
        # Exclude specific fields
        filtered_dict = message.model_dump(exclude={"content"})
        assert "content" not in filtered_dict
        assert "role" in filtered_dict


class TestSchemaGeneration:
    """Test OpenAPI schema generation."""

    def test_generate_openapi_schema(self):
        """Test generating OpenAPI schema from Pydantic models."""
        schema = DetectionResponse.model_json_schema()
        
        assert schema["type"] == "object"
        assert "verdict" in schema["properties"]
        assert "confidence" in schema["properties"]
        
        # Check enum values
        verdict_schema = schema["properties"]["verdict"]
        if "$ref" in verdict_schema:
            # Reference to enum definition
            assert "Verdict" in schema.get("$defs", {})

    def test_schema_examples(self):
        """Test schema with examples."""
        from pydantic import BaseModel, Field
        
        class ExampleModel(BaseModel):
            name: str = Field(
                ...,
                description="User name",
                example="John Doe"
            )
            age: int = Field(
                ...,
                description="User age",
                example=30,
                ge=0,
                le=150
            )
        
        schema = ExampleModel.model_json_schema()
        
        assert schema["properties"]["name"]["example"] == "John Doe"
        assert schema["properties"]["age"]["example"] == 30


if __name__ == "__main__":
    pytest.main([__file__, "-v"])