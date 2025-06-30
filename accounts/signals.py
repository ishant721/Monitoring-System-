
from django.db.models.signals import post_save, pre_save
from django.dispatch import receiver
from django.contrib.auth import get_user_model
import logging

CustomUser = get_user_model()
logger = logging.getLogger(__name__)

@receiver(pre_save, sender=CustomUser)
def handle_admin_deactivation(sender, instance, **kwargs):
    """
    Signal handler that triggers when an admin is being deactivated.
    This ensures cascading deactivation happens automatically.
    """
    if not instance.pk:  # Skip for new users
        return
    
    try:
        # Get the original instance from database
        original = CustomUser.objects.get(pk=instance.pk)
        
        # Check if this is an admin being deactivated
        if (original.role == CustomUser.ADMIN and 
            original.is_active and 
            not instance.is_active):
            
            logger.info(f"Admin {instance.email} is being deactivated - preparing to stop all monitoring")
            
            # Mark this instance so post_save can handle the cascade
            instance._admin_being_deactivated = True
            
    except CustomUser.DoesNotExist:
        pass


@receiver(post_save, sender=CustomUser)
def cascade_admin_deactivation(sender, instance, **kwargs):
    """
    Post-save handler that performs the actual cascading when an admin is deactivated.
    """
    if hasattr(instance, '_admin_being_deactivated') and instance._admin_being_deactivated:
        try:
            from monitor_app.models import Agent
            from mail_monitor.models import EmailAccount, CompanyEmailConfig
            from channels.layers import get_channel_layer
            from asgiref.sync import async_to_sync
            from .utils import send_user_account_status_email
            
            logger.info(f"Cascading deactivation for admin {instance.email}")
            
            # Get all employees under this admin
            employees = CustomUser.objects.filter(
                company_admin=instance, 
                role=CustomUser.USER, 
                is_active=True
            )
            
            channel_layer = get_channel_layer()
            
            # Deactivate all employees and stop their monitoring
            for employee in employees:
                # Deactivate employee
                employee.is_active = False
                employee.save(update_fields=['is_active'])
                
                # Stop all monitoring agents
                user_agents = Agent.objects.filter(user=employee)
                for agent in user_agents:
                    agent.is_activity_monitoring_enabled = False
                    agent.is_network_monitoring_enabled = False
                    agent.is_live_streaming_enabled = False
                    agent.save(update_fields=[
                        'is_activity_monitoring_enabled', 
                        'is_network_monitoring_enabled', 
                        'is_live_streaming_enabled'
                    ])
                    logger.info(f"Disabled monitoring for agent {agent.agent_id} due to admin deactivation")
                
                # Stop email monitoring
                try:
                    email_account = EmailAccount.objects.get(user=employee)
                    if email_account.is_active or email_account.is_authenticated:
                        email_account.is_active = False
                        email_account.is_authenticated = False
                        email_account.save(update_fields=['is_active', 'is_authenticated'])
                        
                        async_to_sync(channel_layer.send)(
                            "email-listener",
                            {"type": "stop.listening", "account_id": email_account.id}
                        )
                        logger.info(f"Stopped email monitoring for employee {employee.email}")
                except EmailAccount.DoesNotExist:
                    pass
                except Exception as e:
                    logger.error(f"Failed to stop email monitoring for employee {employee.email}: {e}")
                
                # Send notification to employee
                send_user_account_status_email(
                    employee,
                    is_activated=False,
                    by_who=instance,
                    reason=f"Company admin account has been deactivated"
                )
            
            # Disable company email configuration
            try:
                company_config = CompanyEmailConfig.objects.get(admin=instance)
                company_config.is_monitoring_enabled = False
                company_config.save(update_fields=['is_monitoring_enabled'])
                logger.info(f"Disabled company email monitoring configuration for {instance.email}")
            except CompanyEmailConfig.DoesNotExist:
                pass
            except Exception as e:
                logger.error(f"Failed to disable company email config for {instance.email}: {e}")
                
            logger.info(f"Completed cascading deactivation for admin {instance.email} - {employees.count()} employees affected")
            
        except Exception as e:
            logger.error(f"Error during cascading admin deactivation for {instance.email}: {e}")
        finally:
            # Clean up the flag
            delattr(instance, '_admin_being_deactivated')
