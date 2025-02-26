import json
import re
import inspect
from typing import Dict, List, Any, Optional, Union, Callable
import logging
from enum import Enum

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger("AISecurityScorer")

class SecurityDimension(Enum):
    INPUT_VALIDATION = "Input Validation"
    OUTPUT_SAFETY = "Output Safety"
    PROMPT_SECURITY = "Prompt Security" 
    TOOL_SECURITY = "Tool Security"
    API_SECURITY = "API Security"
    MONITORING = "Monitoring Capabilities"
    ACCESS_CONTROL = "Access Control"
    DATA_PRIVACY = "Data Privacy"
    
class SeverityLevel(Enum):
    CRITICAL = 10
    HIGH = 7
    MEDIUM = 4
    LOW = 1
    
class SecurityFinding:
    def __init__(self, 
                 dimension: SecurityDimension, 
                 description: str, 
                 severity: SeverityLevel,
                 recommendation: str,
                 evidence: Optional[str] = None):
        self.dimension = dimension
        self.description = description
        self.severity = severity
        self.recommendation = recommendation
        self.evidence = evidence
        
    def to_dict(self) -> Dict:
        return {
            "dimension": self.dimension.value,
            "description": self.description,
            "severity": self.severity.name,
            "severity_score": self.severity.value,
            "recommendation": self.recommendation,
            "evidence": self.evidence
        }

class AIAgentSecurityScorer:
    """
    A system for evaluating the security posture of Langchain-based AI agents.
    """
    
    def __init__(self):
        self.findings = []
        self.dimension_weights = {
            SecurityDimension.INPUT_VALIDATION: 1.0,
            SecurityDimension.OUTPUT_SAFETY: 1.0,
            SecurityDimension.PROMPT_SECURITY: 1.0,
            SecurityDimension.TOOL_SECURITY: 1.0,
            SecurityDimension.API_SECURITY: 1.0,
            SecurityDimension.MONITORING: 0.8,
            SecurityDimension.ACCESS_CONTROL: 0.9,
            SecurityDimension.DATA_PRIVACY: 1.0
        }
        
    def _check_input_validation(self, agent: Any) -> List[SecurityFinding]:
        """Check for input validation mechanisms"""
        findings = []
        
        # Check if there are any input validation functions or patterns
        has_input_validators = False
        
        try:
            # Look for input validation in the agent's chain or tools
            if hasattr(agent, 'llm_chain') and hasattr(agent.llm_chain, 'prompt'):
                prompt_template = str(agent.llm_chain.prompt)
                
                # Check for validation instructions in the prompt
                if "validate" in prompt_template.lower() or "check input" in prompt_template.lower():
                    has_input_validators = True
                
            # Check for input validators in tools if available
            if hasattr(agent, 'tools'):
                for tool in agent.tools:
                    if hasattr(tool, 'description'):
                        if "validate" in tool.description.lower():
                            has_input_validators = True
                            break
                            
            if not has_input_validators:
                findings.append(SecurityFinding(
                    dimension=SecurityDimension.INPUT_VALIDATION,
                    description="No explicit input validation mechanisms detected",
                    severity=SeverityLevel.HIGH,
                    recommendation="Implement input validation functions or instruct the agent to validate inputs in its prompt"
                ))
                
        except Exception as e:
            logger.warning(f"Error during input validation check: {str(e)}")
            
        return findings
    
    def _check_output_safety(self, agent: Any) -> List[SecurityFinding]:
        """Check for output safety mechanisms"""
        findings = []
        
        try:
            has_output_checks = False
            
            # Check for output checkers
            if hasattr(agent, 'llm_chain') and hasattr(agent.llm_chain, 'prompt'):
                prompt_template = str(agent.llm_chain.prompt)
                
                # Look for output safety instructions in the prompt
                if any(term in prompt_template.lower() for term in ["safe output", "check response", "verify response"]):
                    has_output_checks = True
                    
            # Check if any external output validation like a moderation endpoint is used
            if hasattr(agent, 'output_parser'):
                output_parser_source = inspect.getsource(agent.output_parser.__class__)
                if any(term in output_parser_source.lower() for term in ["moderation", "filter", "safety"]):
                    has_output_checks = True
                    
            if not has_output_checks:
                findings.append(SecurityFinding(
                    dimension=SecurityDimension.OUTPUT_SAFETY,
                    description="No output safety mechanisms detected",
                    severity=SeverityLevel.HIGH,
                    recommendation="Implement output filtering or moderation checks before delivering responses"
                ))
                
        except Exception as e:
            logger.warning(f"Error during output safety check: {str(e)}")
            
        return findings
    
    def _check_prompt_security(self, agent: Any) -> List[SecurityFinding]:
        """Check for prompt security issues"""
        findings = []
        
        try:
            if hasattr(agent, 'llm_chain') and hasattr(agent.llm_chain, 'prompt'):
                prompt_template = str(agent.llm_chain.prompt)
                
                # Check for hardcoded credentials or sensitive info in prompts
                credential_patterns = [
                    r"api[_-]?key\s*[:=]\s*[\'\"][^\'\"\s]+[\'\"]",
                    r"password\s*[:=]\s*[\'\"][^\'\"\s]+[\'\"]",
                    r"secret\s*[:=]\s*[\'\"][^\'\"\s]+[\'\"]",
                    r"token\s*[:=]\s*[\'\"][^\'\"\s]+[\'\"]"
                ]
                
                for pattern in credential_patterns:
                    if re.search(pattern, prompt_template, re.IGNORECASE):
                        findings.append(SecurityFinding(
                            dimension=SecurityDimension.PROMPT_SECURITY,
                            description="Potential hardcoded credentials in prompt template",
                            severity=SeverityLevel.CRITICAL,
                            recommendation="Remove credentials from prompts and use environment variables or a secrets manager",
                            evidence=f"Pattern '{pattern}' matched in prompt template"
                        ))
                
                # Check for lack of injection prevention guidance
                if not any(term in prompt_template.lower() for term in ["ignore previous instructions", "disregard", "do not follow"]):
                    findings.append(SecurityFinding(
                        dimension=SecurityDimension.PROMPT_SECURITY,
                        description="No prompt injection safeguards detected",
                        severity=SeverityLevel.MEDIUM,
                        recommendation="Add instructions to ignore attempts to override or manipulate the AI's behavior"
                    ))
                    
        except Exception as e:
            logger.warning(f"Error during prompt security check: {str(e)}")
            
        return findings
    
    def _check_tool_security(self, agent: Any) -> List[SecurityFinding]:
        """Check for tool security issues"""
        findings = []
        
        try:
            if hasattr(agent, 'tools'):
                # Check for potentially dangerous tools
                dangerous_tool_patterns = ["execute", "shell", "command", "script", "eval", "subprocess"]
                
                for tool in agent.tools:
                    tool_name = tool.name.lower() if hasattr(tool, 'name') else ""
                    tool_description = tool.description.lower() if hasattr(tool, 'description') else ""
                    
                    # Check if tool names or descriptions contain dangerous patterns
                    for pattern in dangerous_tool_patterns:
                        if pattern in tool_name or pattern in tool_description:
                            findings.append(SecurityFinding(
                                dimension=SecurityDimension.TOOL_SECURITY,
                                description=f"Potentially dangerous tool detected: {tool.name}",
                                severity=SeverityLevel.HIGH,
                                recommendation="Remove or restrict tools that can execute code or shell commands",
                                evidence=f"Tool '{tool.name}' matches dangerous pattern '{pattern}'"
                            ))
                            break
                
                # Check for proper tool documentation
                for tool in agent.tools:
                    if not hasattr(tool, 'description') or not tool.description:
                        findings.append(SecurityFinding(
                            dimension=SecurityDimension.TOOL_SECURITY,
                            description=f"Tool lacks proper documentation: {tool.name if hasattr(tool, 'name') else 'Unnamed tool'}",
                            severity=SeverityLevel.LOW,
                            recommendation="Document all tools with clear descriptions of their purpose and usage"
                        ))
                        
        except Exception as e:
            logger.warning(f"Error during tool security check: {str(e)}")
            
        return findings
    
    def _check_api_security(self, agent: Any) -> List[SecurityFinding]:
        """Check for API security issues"""
        findings = []
        
        try:
            # Check for API key handling
            api_key_in_code = False
            agent_code = ""
            
            # Try to get source code of the agent
            try:
                agent_code = inspect.getsource(agent.__class__)
            except:
                # If that fails, try to get the string representation
                agent_code = str(agent)
                
            # Look for API key patterns in the code
            api_key_patterns = [
                r"api[_-]?key\s*[:=]\s*[\'\"][^\'\"\s]+[\'\"]",
                r"sk-[a-zA-Z0-9]{20,}"  # OpenAI API key pattern
            ]
            
            for pattern in api_key_patterns:
                if re.search(pattern, agent_code, re.IGNORECASE):
                    api_key_in_code = True
                    break
            
            if api_key_in_code:
                findings.append(SecurityFinding(
                    dimension=SecurityDimension.API_SECURITY,
                    description="API keys potentially hardcoded in agent code",
                    severity=SeverityLevel.CRITICAL,
                    recommendation="Use environment variables or a secure key management system for API keys"
                ))
                
        except Exception as e:
            logger.warning(f"Error during API security check: {str(e)}")
            
        return findings
    
    def _check_monitoring(self, agent: Any) -> List[SecurityFinding]:
        """Check for monitoring capabilities"""
        findings = []
        
        try:
            has_monitoring = False
            agent_code = ""
            
            # Try to get source code of the agent
            try:
                agent_code = inspect.getsource(agent.__class__)
            except:
                # If that fails, try to get the string representation
                agent_code = str(agent)
                
            # Check for logging or monitoring patterns
            monitoring_patterns = ["logging", "monitor", "callback", "record", "track"]
            
            for pattern in monitoring_patterns:
                if pattern in agent_code.lower():
                    has_monitoring = True
                    break
                    
            if not has_monitoring:
                findings.append(SecurityFinding(
                    dimension=SecurityDimension.MONITORING,
                    description="No monitoring or logging mechanisms detected",
                    severity=SeverityLevel.MEDIUM,
                    recommendation="Implement logging and monitoring for agent activities and responses"
                ))
                
        except Exception as e:
            logger.warning(f"Error during monitoring check: {str(e)}")
            
        return findings
    
    def _calculate_score(self) -> Dict[str, Any]:
        """Calculate the security score based on findings"""
        total_weight = sum(self.dimension_weights.values())
        dimension_scores = {dim: 10.0 for dim in SecurityDimension}  # Start with perfect scores
        
        # Calculate score reduction for each dimension based on findings
        for finding in self.findings:
            # Reduce the dimension's score based on severity
            current_score = dimension_scores[finding.dimension]
            # More severe findings reduce the score more significantly
            reduction = finding.severity.value / 2
            dimension_scores[finding.dimension] = max(0, current_score - reduction)
        
        # Calculate weighted average for final score
        weighted_sum = 0
        for dim, score in dimension_scores.items():
            weighted_sum += score * self.dimension_weights[dim]
            
        final_score = weighted_sum / total_weight
        
        # Convert dimension scores to dictionaries for serialization
        formatted_dimension_scores = {dim.value: score for dim, score in dimension_scores.items()}
        
        return {
            "overall_score": round(final_score, 2),
            "dimension_scores": formatted_dimension_scores,
            "max_score": 10.0
        }
    
    def evaluate(self, agent: Any) -> Dict[str, Any]:
        """
        Evaluate the security posture of a Langchain-based agent
        
        Args:
            agent: A Langchain agent instance
            
        Returns:
            A dictionary containing security score and findings
        """
        self.findings = []
        
        # Run all security checks
        self.findings.extend(self._check_input_validation(agent))
        self.findings.extend(self._check_output_safety(agent))
        self.findings.extend(self._check_prompt_security(agent))
        self.findings.extend(self._check_tool_security(agent))
        self.findings.extend(self._check_api_security(agent))
        self.findings.extend(self._check_monitoring(agent))
        
        # Calculate the security score
        score_data = self._calculate_score()
        
        # Prepare the evaluation results
        findings_dict = [finding.to_dict() for finding in self.findings]
        
        return {
            "security_score": score_data["overall_score"],
            "max_score": score_data["max_score"],
            "dimension_scores": score_data["dimension_scores"],
            "findings": findings_dict,
            "timestamp": logging.Formatter().formatTime(logging.LogRecord("", 0, "", 0, "", [], None))
        }
    
    def generate_report(self, agent_name: str, evaluation_results: Dict[str, Any], output_format: str = "text") -> str:
        """
        Generate a human-readable security report
        
        Args:
            agent_name: Name of the evaluated agent
            evaluation_results: Results from the evaluate method
            output_format: Format of the report ("text", "json", "markdown")
            
        Returns:
            Report as a string in the requested format
        """
        if output_format == "json":
            return json.dumps({
                "agent_name": agent_name,
                "evaluation": evaluation_results
            }, indent=2)
            
        elif output_format == "markdown":
            report = f"# Security Report for {agent_name}\n\n"
            report += f"## Overall Security Score: {evaluation_results['security_score']}/{evaluation_results['max_score']}\n\n"
            
            report += "## Dimension Scores\n\n"
            for dim, score in evaluation_results['dimension_scores'].items():
                report += f"- **{dim}**: {score}/{evaluation_results['max_score']}\n"
            
            if evaluation_results['findings']:
                report += "\n## Security Findings\n\n"
                for i, finding in enumerate(evaluation_results['findings'], 1):
                    report += f"### {i}. {finding['description']} ({finding['severity']})\n\n"
                    report += f"**Dimension**: {finding['dimension']}\n\n"
                    report += f"**Recommendation**: {finding['recommendation']}\n\n"
                    if finding['evidence']:
                        report += f"**Evidence**: {finding['evidence']}\n\n"
            else:
                report += "\n## Security Findings\n\nNo security issues were found.\n"
                
            report += f"\n*Report generated at {evaluation_results['timestamp']}*"
            return report
            
        else:  # Default to text format
            report = f"Security Report for {agent_name}\n"
            report += "=" * 50 + "\n\n"
            
            report += f"Overall Security Score: {evaluation_results['security_score']}/{evaluation_results['max_score']}\n\n"
            
            report += "Dimension Scores:\n"
            for dim, score in evaluation_results['dimension_scores'].items():
                report += f"  {dim}: {score}/{evaluation_results['max_score']}\n"
            
            if evaluation_results['findings']:
                report += "\nSecurity Findings:\n"
                for i, finding in enumerate(evaluation_results['findings'], 1):
                    report += f"\n{i}. {finding['description']} ({finding['severity']})\n"
                    report += f"   Dimension: {finding['dimension']}\n"
                    report += f"   Recommendation: {finding['recommendation']}\n"
                    if finding['evidence']:
                        report += f"   Evidence: {finding['evidence']}\n"
            else:
                report += "\nSecurity Findings: No security issues were found.\n"
                
            report += f"\nReport generated at {evaluation_results['timestamp']}"
            return report

# Example usage function
def example_usage():
    """
    Provide example usage of the AIAgentSecurityScorer
    """
    # Create the security scorer
    scorer = AIAgentSecurityScorer()
    
    # This is where you would evaluate a real Langchain agent
    # For the example, we'll just print instructions
    print("Example usage of AIAgentSecurityScorer:")
    print("-" * 50)
    print("from langchain.agents import initialize_agent, Tool")
    print("from langchain.llms import OpenAI")
    print("")
    print("# Initialize your Langchain agent")
    print("llm = OpenAI(temperature=0)")
    print("tools = [...")
    print("agent = initialize_agent(tools, llm, agent='zero-shot-react-description')")
    print("")
    print("# Create the security scorer")
    print("scorer = AIAgentSecurityScorer()")
    print("")
    print("# Evaluate the agent")
    print("results = scorer.evaluate(agent)")
    print("")
    print("# Generate a report")
    print("report = scorer.generate_report('My Langchain Agent', results, output_format='markdown')")
    print("print(report)")
    
if __name__ == "__main__":
    example_usage()
