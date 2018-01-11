using Microsoft.Extensions.Logging;
using Newtonsoft.Json.Linq;
using PrivacyABAC.Core.Model;
using PrivacyABAC.DbInterfaces.Model;
using PrivacyABAC.DbInterfaces.Repository;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace PrivacyABAC.Core.Service
{
    public class AccessControlService
    {
        private readonly IAccessControlPolicyRepository _accessControlPolicyRepository;
        private readonly ConditionalExpressionService _expressionService;
        private readonly IPolicyCombiningRepository _policyCombiningRepository;
        private readonly ILogger<AccessControlService> _logger;

        public AccessControlService(
            IAccessControlPolicyRepository accessControlPolicyRepository,
            ConditionalExpressionService expressionService,
            IPolicyCombiningRepository policyCombiningRepository,
            ILogger<AccessControlService> logger)
        {
            _accessControlPolicyRepository = accessControlPolicyRepository;
            _expressionService = expressionService;
            _policyCombiningRepository = policyCombiningRepository;
            _logger = logger;
        }

        public AccessControlResponseContext ExecuteProcess(Subject subject, Resource resource, string action, EnvironmentObject environment)
        {
            environment.Data.AddAnnotation(action);

            var permitPolicies = new List<AccessControlPolicy>();
            var denyPolicies = new List<AccessControlPolicy>();

            IEnumerable<string> afterObligationIds = null;
            IEnumerable<string> beforeObligationIds = null;

            AccessControlEffect collectionEffect = AccessControlProcess(subject, resource, action, environment,ref permitPolicies, ref denyPolicies);

            if (collectionEffect == AccessControlEffect.Permit)
            {
                afterObligationIds = permitPolicies.SelectMany(n => n.ObligationAfterIds);
                beforeObligationIds = permitPolicies.SelectMany(n => n.ObligationBeforeIds);
            }
            else if (collectionEffect == AccessControlEffect.Deny)
            {
                afterObligationIds = denyPolicies.SelectMany(n => n.ObligationAfterIds);
                beforeObligationIds = denyPolicies.SelectMany(n => n.ObligationBeforeIds);
            }

            return new AccessControlResponseContext(collectionEffect, null, afterObligationIds, beforeObligationIds);
        }

        private AccessControlEffect CollectionAccessControlProcess(
            Subject subject, 
            Resource resource, 
            string action, 
            EnvironmentObject environment, 
            ref List<AccessControlPolicy> permitPolicies, 
            ref List<AccessControlPolicy> denyPolicies)
        {
            AccessControlEffect result = AccessControlEffect.NotApplicable;

            ICollection<AccessControlPolicy> collectionPolicies = _accessControlPolicyRepository.Get(resource.Name, action, false);

            string policyCombining = _policyCombiningRepository.GetRuleCombining(collectionPolicies);

            var targetPolicies = new List<AccessControlPolicy>();
            foreach (var policy in collectionPolicies)
            {
                bool isTarget = _expressionService.Evaluate(policy.Target, subject.Data, null, environment.Data);
                if (isTarget)
                    targetPolicies.Add(policy);
            }

            foreach (var policy in targetPolicies)
            {
                string policyEffect = String.Empty;

                foreach (var rule in policy.Rules)
                {
                    bool isApplied = _expressionService.Evaluate(rule.Condition, subject.Data, null, environment.Data);
                    if (isApplied && rule.Effect.Equals("Permit") && policy.RuleCombining.Equals("permit-overrides"))
                    {
                        policyEffect = "Permit";
                        break;
                    }
                    if (isApplied && rule.Effect.Equals("Deny") && policy.RuleCombining.Equals("deny-overrides"))
                    {
                        policyEffect = "Deny";
                        break;
                    }
                }
                if (policyEffect.Equals("Permit") && policyCombining.Equals("permit-overrides"))
                {
                    result = AccessControlEffect.Permit;
                    break;
                }
                else if (policyEffect.Equals("Deny") && policyCombining.Equals("deny-overrides"))
                {
                    result = AccessControlEffect.Deny;
                    break;
                }
                // add retaive policy here
            }
            return result;
        }
        
        private JObject RowAccessControlProcess(Subject subject, JObject resource, EnvironmentObject environment, string policyCombining, ICollection<AccessControlPolicy> policies)
        {
            JObject result = null;
            var targetPolicy = new List<AccessControlPolicy>();
            foreach (var policy in policies)
            {
                bool isTarget = _expressionService.Evaluate(policy.Target, subject.Data, resource, environment.Data);
                if (isTarget)
                    targetPolicy.Add(policy);
            }
            foreach (var policy in targetPolicy)
            {
                string effect = String.Empty;

                foreach (var rule in policy.Rules)
                {
                    bool isApplied = _expressionService.Evaluate(rule.Condition, subject.Data, resource, environment.Data);
                    if (isApplied && rule.Effect.Equals(RuleEffect.PERMIT) && policy.RuleCombining.Equals(AlgorithmCombining.PERMIT_OVERRIDES))
                    {
                        effect = RuleEffect.PERMIT;
                        break;
                    }
                    if (isApplied && rule.Effect.Equals(RuleEffect.DENY) && policy.RuleCombining.Equals(AlgorithmCombining.DENY_OVERRIDES))
                    {
                        effect = RuleEffect.DENY;
                        break;
                    }
                }
                if (effect.Equals(RuleEffect.PERMIT) && policyCombining.Equals(AlgorithmCombining.PERMIT_OVERRIDES))
                {
                    result = resource;
                    break;
                }
                else if (effect.Equals(RuleEffect.DENY) && policyCombining.Equals(AlgorithmCombining.DENY_OVERRIDES))
                {
                    result = null;
                    break;
                }
            }
            return result;
        }

        private AccessControlEffect AccessControlProcess(
            Subject subject,
            Resource resource,
            string action,
            EnvironmentObject environment,
            ref List<AccessControlPolicy> permitPolicies,
            ref List<AccessControlPolicy> denyPolicies)
        {
            AccessControlEffect result = AccessControlEffect.NotApplicable;

            ICollection<AccessControlPolicy> collectionPolicies = _accessControlPolicyRepository.Get(resource.Name, action, null);

            string policyCombining = _policyCombiningRepository.GetRuleCombining(collectionPolicies);
            var resourceData = resource.Data[0];

            var targetPolicies = new List<AccessControlPolicy>();
            foreach (var policy in collectionPolicies)
            {
                bool isTarget = _expressionService.Evaluate(policy.Target, subject.Data, resourceData, environment.Data);
                if (isTarget)
                    targetPolicies.Add(policy);
            }

            foreach (var policy in targetPolicies)
            {
                string policyEffect = String.Empty;

                foreach (var rule in policy.Rules)
                {
                    bool isApplied = _expressionService.Evaluate(rule.Condition, subject.Data, resourceData, environment.Data);
                    if (isApplied && rule.Effect.Equals("Permit") && policy.RuleCombining.Equals("permit-overrides"))
                    {
                        policyEffect = "Permit";
                        break;
                    }
                    if (isApplied && rule.Effect.Equals("Deny") && policy.RuleCombining.Equals("deny-overrides"))
                    {
                        policyEffect = "Deny";
                        break;
                    }
                }
                if (policyEffect.Equals("Permit"))
                {
                    permitPolicies.Add(policy);
                    if (policyCombining.Equals("permit-overrides"))
                    {
                        result = AccessControlEffect.Permit;
                        break;
                    }
                }
                else if (policyEffect.Equals("Deny"))
                {
                    denyPolicies.Add(policy);
                    if (policyCombining.Equals("deny-overrides"))
                    {
                        result = AccessControlEffect.Deny;
                        break;
                    }
                }
            }
            return result;
        }

        public ICollection<AccessControlPolicy> Review(JObject user, JObject resource, JObject environment)
        {
            var policies = _accessControlPolicyRepository.GetAll();
            var result = new List<AccessControlPolicy>();
            foreach (var policy in policies)
            {
                if (_expressionService.IsAccessControlPolicyRelateToContext(policy, user, resource, environment))
                    result.Add(policy);
            }
            return result;
        }
    }
}
