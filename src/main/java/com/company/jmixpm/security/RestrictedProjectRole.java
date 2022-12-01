package com.company.jmixpm.security;

import com.company.jmixpm.entity.Project;
import com.company.jmixpm.entity.User;
import io.jmix.core.security.CurrentAuthentication;
import io.jmix.security.model.RowLevelBiPredicate;
import io.jmix.security.model.RowLevelPolicyAction;
import io.jmix.security.role.annotation.PredicateRowLevelPolicy;
import io.jmix.security.role.annotation.RowLevelRole;
import org.springframework.context.ApplicationContext;

@RowLevelRole(name = "RestrictedProjectRole", code = "restricted-project-role")
public interface RestrictedProjectRole {

    @PredicateRowLevelPolicy(entityClass = Project.class, actions = {
            RowLevelPolicyAction.UPDATE,
            RowLevelPolicyAction.DELETE}
    )
    default RowLevelBiPredicate<Project, ApplicationContext> projectPredicate() {
        return (project, applicationContext) -> {
            CurrentAuthentication authentication = applicationContext.getBean(CurrentAuthentication.class);
            User user = ((User) authentication.getUser());
            return user.equals(project.getManager());
        };
    }
}